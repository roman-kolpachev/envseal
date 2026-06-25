package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/roman-kolpachev/envseal/internal/config"
	"github.com/roman-kolpachev/envseal/internal/crypto"
	"github.com/roman-kolpachev/envseal/internal/dotenv"
	"github.com/roman-kolpachev/envseal/internal/envcheck"
	"github.com/roman-kolpachev/envseal/internal/fileutil"
)

const maxValueSize = 1024 * 1024 // 1 MiB

// vaultFormatVersion is the only supported vault file format. Version 4
// binds each entry to its environment AND key name by encrypting
// "environment\x00key\x00value" instead of the bare value. Verifying either
// binding requires decrypting the entry, so (unlike v2's plaintext HMAC+salt)
// it is not an offline verification oracle for an attacker who only has the
// vault file. The environment binding makes whole-file swaps (staging.vault
// copied over production.vault) cryptographically detectable: the plaintext
// "environment" JSON field is attacker-editable, but the name embedded inside
// every entry's ciphertext is not.
const vaultFormatVersion = 4

var (
	ErrKeyNotFound    = errors.New("key not found in vault")
	ErrVaultNotFound  = errors.New("vault file not found")
	ErrNoRecipients   = errors.New("no recipients configured")
	ErrInvalidKeyName = errors.New("key name must match [A-Za-z_][A-Za-z0-9_]*")
	ErrValueTooLarge  = errors.New("value exceeds maximum size")
	// ErrEntryIntegrity indicates that the environment or key name embedded in
	// a decrypted entry's plaintext does not match the environment/key it was
	// stored under — the entry was moved to a different key, copied from
	// another environment's vault, or otherwise tampered with.
	ErrEntryIntegrity = errors.New("entry integrity check failed — the encrypted value does not match this environment and key (entries may have been swapped, copied from another environment, or the vault file tampered with)")
	// ErrNoEnvironment indicates a Service method that encrypts or verifies
	// entries was called before SetEnvironment bound the service to an
	// environment name. Failing closed here (instead of silently encrypting
	// with an empty binding) is what makes the per-entry environment binding
	// impossible to forget at a call site.
	ErrNoEnvironment = errors.New("vault service is not bound to an environment — call SetEnvironment first")

	validKeyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type Entry struct {
	Encrypted string `json:"encrypted"`
}

type Vault struct {
	Version     int              `json:"version"`
	Environment string           `json:"environment"`
	CreatedAt   string           `json:"created_at"`
	UpdatedAt   string           `json:"updated_at"`
	Entries     map[string]Entry `json:"entries"`
}

type DiffResult struct {
	Key    string `json:"key"`
	Status string `json:"status"`
}

type ConflictChoice int

const (
	ConflictYes ConflictChoice = iota
	ConflictNo
	ConflictAll
)

type OnConflict func(key string) ConflictChoice

type ImportResult struct {
	Imported []string
	Skipped  []string
	Total    int
}

type SyncResult struct {
	Added     []string
	Changed   []string
	Removed   []string
	Kept      []string
	Unchanged []string
}

type Service struct {
	enc crypto.Encryptor
	cfg *config.Config
	// environment is the environment name this service instance is bound to.
	// It is embedded into (and verified against) every entry's encrypted
	// plaintext — see encodeEntryPlaintext. Set via SetEnvironment; methods
	// that encrypt or decrypt entries fail with ErrNoEnvironment while empty.
	environment string
	vault       *Vault
}

func NewService(enc crypto.Encryptor, cfg *config.Config) *Service {
	return &Service{
		enc: enc,
		cfg: cfg,
		vault: &Vault{
			Version:   vaultFormatVersion,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Entries:   make(map[string]Entry),
		},
	}
}

func (s *Service) Encryptor() crypto.Encryptor {
	return s.enc
}

// SetEnvironment binds the service to an environment name. Every subsequent
// Set embeds the name into the entry's encrypted plaintext and every Get
// verifies it, so entries from one environment's vault cannot be decrypted as
// another's. Must be called before Load/Set/Get/DecryptAll/ReEncryptAll.
func (s *Service) SetEnvironment(environment string) error {
	if err := config.ValidateEnvironmentName(environment); err != nil {
		return err
	}
	s.environment = environment
	return nil
}

// Environment returns the environment name recorded in the loaded vault file
// ("" if the vault is new). Callers use it as a fast, pre-decryption check
// for a vault file copied from another environment; the authoritative check
// is the per-entry binding verified on every decrypt.
func (s *Service) Environment() string {
	return s.vault.Environment
}

func (s *Service) Reset() {
	s.vault = &Vault{
		Version:   vaultFormatVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Entries:   make(map[string]Entry),
	}
}

const maxKeyNameLength = 256

func ValidateKeyName(key string) error {
	if len(key) > maxKeyNameLength {
		return fmt.Errorf("%q: key name exceeds maximum length of %d characters", key, maxKeyNameLength)
	}
	if !validKeyName.MatchString(key) {
		return fmt.Errorf("%q: %w", key, ErrInvalidKeyName)
	}
	return nil
}

var ErrDangerousKey = errors.New("key overrides a dangerous system variable — set it directly in your environment instead")

func (s *Service) Set(ctx context.Context, key string, value []byte) error {
	if s.environment == "" {
		return ErrNoEnvironment
	}
	if err := ValidateKeyName(key); err != nil {
		return err
	}
	if envcheck.IsDangerous(key) {
		return fmt.Errorf("%q: %w", key, ErrDangerousKey)
	}
	if len(value) > maxValueSize {
		return fmt.Errorf("%q: %w (max %d bytes)", key, ErrValueTooLarge, maxValueSize)
	}
	if bytes.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%q: value contains null bytes which are not supported in environment variables", key)
	}
	if _, exists := s.vault.Entries[key]; !exists && len(s.vault.Entries) >= maxVaultEntries {
		return fmt.Errorf("vault already contains %d entries (maximum %d)", len(s.vault.Entries), maxVaultEntries)
	}

	recipients := s.cfg.RecipientKeys()
	if len(recipients) == 0 {
		return ErrNoRecipients
	}

	// The framed buffer holds a copy of the secret value; zero it as soon as
	// encryption is done (on both success and error paths).
	framed := encodeEntryPlaintext(s.environment, key, value)
	encrypted, err := s.enc.Encrypt(framed, recipients)
	clear(framed)
	if err != nil {
		return fmt.Errorf("encrypt %q: %w", key, err)
	}

	s.vault.Entries[key] = Entry{
		Encrypted: encrypted,
	}
	s.vault.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// encodeEntryPlaintext frames an environment- and key-bound plaintext as
// "environment\x00key\x00value" before it is age-encrypted. Environment names
// are validated to [a-zA-Z0-9_-] (config.ValidateEnvironmentName), key names
// to [A-Za-z0-9_], and values are rejected if they contain a null byte (see
// Set), so 0x00 can never occur inside any part — the splits in
// decodeEntryPlaintext are unambiguous.
//
// Binding both names to the ciphertext this way (instead of a separate
// plaintext hash, as the v2 format did) means verifying the binding requires
// decrypting the entry: an attacker holding only the vault file cannot check
// guesses offline. Swapping two entries' ciphertexts is caught because the
// embedded key no longer matches, and copying a whole vault file (or a single
// ciphertext) across environments is caught because the embedded environment
// no longer matches — the plaintext "environment" JSON field can be forged,
// but the name inside the ciphertext cannot.
func encodeEntryPlaintext(environment, key string, value []byte) []byte {
	buf := make([]byte, 0, len(environment)+1+len(key)+1+len(value))
	buf = append(buf, environment...)
	buf = append(buf, 0)
	buf = append(buf, key...)
	buf = append(buf, 0)
	buf = append(buf, value...)
	return buf
}

// decodeEntryPlaintext splits a decrypted entry plaintext back into its
// environment, key, and value. The returned value aliases plaintext's backing
// array.
func decodeEntryPlaintext(plaintext []byte) (environment, key string, value []byte, err error) {
	i := bytes.IndexByte(plaintext, 0)
	if i < 0 {
		return "", "", nil, fmt.Errorf("malformed entry: missing environment separator")
	}
	rest := plaintext[i+1:]
	j := bytes.IndexByte(rest, 0)
	if j < 0 {
		return "", "", nil, fmt.Errorf("malformed entry: missing key separator")
	}
	return string(plaintext[:i]), string(rest[:j]), rest[j+1:], nil
}

func (s *Service) Get(ctx context.Context, key string) ([]byte, error) {
	if s.environment == "" {
		return nil, ErrNoEnvironment
	}
	entry, ok := s.vault.Entries[key]
	if !ok {
		return nil, ErrKeyNotFound
	}

	plaintext, err := s.enc.Decrypt(entry.Encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt %q: %w", key, err)
	}

	value, err := verifyEntry(s.environment, key, plaintext)
	if err != nil {
		clear(plaintext)
		return nil, err
	}

	return value, nil
}

// verifyEntry checks that the decrypted plaintext's embedded environment and
// key name match the environment the service is bound to and the map key the
// entry was stored under, returning the value with the binding prefix
// stripped. A mismatch (or malformed framing) means the entry was swapped,
// copied from another environment, or otherwise tampered with — never
// silently accepted.
func verifyEntry(environment, key string, plaintext []byte) ([]byte, error) {
	gotEnv, gotKey, value, err := decodeEntryPlaintext(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%q: entry lacks an environment- and key-bound plaintext: %w", key, ErrEntryIntegrity)
	}
	if gotEnv != environment || gotKey != key {
		return nil, fmt.Errorf("%q: %w", key, ErrEntryIntegrity)
	}
	return value, nil
}

func (s *Service) Remove(key string) error {
	if _, ok := s.vault.Entries[key]; !ok {
		return ErrKeyNotFound
	}
	delete(s.vault.Entries, key)
	s.vault.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

func (s *Service) List() ([]string, error) {
	keys := make([]string, 0, len(s.vault.Entries))
	for k := range s.vault.Entries {
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Service) Import(ctx context.Context, dotenvPath string, onConflict OnConflict) (*ImportResult, error) {
	entries, err := dotenv.ParseFile(dotenvPath)
	if err != nil {
		return nil, fmt.Errorf("parse dotenv: %w", err)
	}
	defer clearDotenvEntries(entries)
	return s.ImportEntries(ctx, entries, onConflict)
}

func clearDotenvEntries(entries []dotenv.Entry) {
	for i := range entries {
		clear(entries[i].Value)
	}
	clear(entries)
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (s *Service) ImportEntries(ctx context.Context, entries []dotenv.Entry, onConflict OnConflict) (*ImportResult, error) {
	result := &ImportResult{Total: len(entries)}
	overwriteAll := false

	for _, e := range entries {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		if _, exists := s.vault.Entries[e.Key]; exists {
			if overwriteAll {
				// fall through to Set
			} else if onConflict != nil {
				switch onConflict(e.Key) {
				case ConflictNo:
					result.Skipped = append(result.Skipped, e.Key)
					continue
				case ConflictAll:
					overwriteAll = true
				}
			} else {
				result.Skipped = append(result.Skipped, e.Key)
				continue
			}
		}
		if err := s.Set(ctx, e.Key, e.Value); err != nil {
			return nil, err
		}
		result.Imported = append(result.Imported, e.Key)
	}

	return result, nil
}

func (s *Service) Sync(ctx context.Context, dotenvPath string, prune bool, onConflict OnConflict) (*SyncResult, error) {
	entries, err := dotenv.ParseFile(dotenvPath)
	if err != nil {
		return nil, fmt.Errorf("parse dotenv: %w", err)
	}
	defer clearDotenvEntries(entries)

	result := &SyncResult{}
	seen := make(map[string]bool)
	overwriteAll := false

	for _, e := range entries {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		seen[e.Key] = true

		_, exists := s.vault.Entries[e.Key]
		if exists {
			if !overwriteAll {
				if onConflict == nil {
					result.Unchanged = append(result.Unchanged, e.Key)
					continue
				}
				switch onConflict(e.Key) {
				case ConflictNo:
					result.Unchanged = append(result.Unchanged, e.Key)
					continue
				case ConflictAll:
					overwriteAll = true
				}
			}
			result.Changed = append(result.Changed, e.Key)
		} else {
			result.Added = append(result.Added, e.Key)
		}

		if err := s.Set(ctx, e.Key, e.Value); err != nil {
			return nil, err
		}
	}

	for key := range s.vault.Entries {
		if !seen[key] {
			if prune {
				result.Removed = append(result.Removed, key)
				delete(s.vault.Entries, key)
			} else {
				result.Kept = append(result.Kept, key)
			}
		}
	}

	return result, nil
}

func (s *Service) DecryptAll(ctx context.Context) (map[string][]byte, error) {
	result := make(map[string][]byte, len(s.vault.Entries))
	for key := range s.vault.Entries {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		val, err := s.Get(ctx, key)
		if err != nil {
			ClearSecretMap(result)
			return nil, err
		}
		result[key] = val
	}
	return result, nil
}

func ClearSecretMap(m map[string][]byte) {
	for k, v := range m {
		clear(v)
		delete(m, k)
	}
}

func (s *Service) Diff(dotenvPath string) ([]DiffResult, error) {
	entries, err := dotenv.ParseFile(dotenvPath)
	if err != nil {
		return nil, fmt.Errorf("parse dotenv: %w", err)
	}
	defer clearDotenvEntries(entries)

	var diffs []DiffResult
	seen := make(map[string]bool)

	for _, e := range entries {
		seen[e.Key] = true

		if _, exists := s.vault.Entries[e.Key]; !exists {
			diffs = append(diffs, DiffResult{Key: e.Key, Status: "added"})
		} else if s.hasChanged(e.Key, e.Value) {
			diffs = append(diffs, DiffResult{Key: e.Key, Status: "changed"})
		} else {
			diffs = append(diffs, DiffResult{Key: e.Key, Status: "unchanged"})
		}
	}

	for key := range s.vault.Entries {
		if !seen[key] {
			diffs = append(diffs, DiffResult{Key: key, Status: "removed"})
		}
	}

	return diffs, nil
}

var validExportFormats = map[string]bool{
	"json": true, "shell": true, "docker": true, "k8s": true,
}

func (s *Service) Export(ctx context.Context, format string, w io.Writer) error {
	if !validExportFormats[format] {
		return fmt.Errorf("unknown export format: %q", format)
	}

	all, err := s.DecryptAll(ctx)
	if err != nil {
		return err
	}
	defer ClearSecretMap(all)

	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if envcheck.IsDangerous(k) {
			return fmt.Errorf(
				"vault contains dangerous environment variable %q — remove it with `envseal rm %s` before exporting",
				k, k,
			)
		}
	}

	switch format {

	case "json":
		// JSON strings must be valid UTF-8 (RFC 8259). Set only rejects null
		// bytes, so a value can otherwise hold arbitrary bytes (e.g. via a
		// dotenv \xHH escape). Silently passing such bytes through would
		// either emit invalid UTF-8(parser-dependent behaviour downstream)
		// or, if we instead substituted a replacement character, corrupt the
		// actual secret value. Failing closed with a clear error is the only
		// option that doesn't risk mangling secret material.
		for _, k := range keys {
			if !utf8.Valid(all[k]) {
				return fmt.Errorf(
					"secret %q contains non-UTF-8 bytes and cannot be represented in JSON — use --format shell or --format docker instead",
					k,
				)
			}
		}
		// writeSecretsJSON encodes directly from []byte values so that
		// intermediate string copies (which are immutable and cannot be zeroed)
		// are never created. The caller already holds a defer on ClearSecretMap.
		return writeSecretsJSON(w, keys, all)

	case "shell":
		for _, k := range keys {
			if _, err := fmt.Fprintf(w, "export %s='", k); err != nil {
				return err
			}
			if err := writeShellEscapedBytes(w, all[k]); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, "'"); err != nil {
				return err
			}
		}
		return nil

	case "docker":
		for _, k := range keys {
			if _, err := fmt.Fprintf(w, "%s=\"", k); err != nil {
				return err
			}
			if err := writeDockerEscapedBytes(w, all[k]); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, "\""); err != nil {
				return err
			}
		}
		return nil

	case "k8s":
		// Use base64-encoded "data:" instead of "stringData:" with Go %q quoting.
		// Go's %q emits \xHH escapes for non-ASCII bytes which YAML 1.1 parsers
		// (used by many Kubernetes client libraries) do not support. Base64 is the
		// canonical binary-safe encoding for Kubernetes Secret data fields.
		for _, line := range []string{
			"apiVersion: v1",
			"kind: Secret",
			"metadata:",
			"  name: app-secrets",
			"type: Opaque",
			"data:",
		} {
			if _, err := fmt.Fprintln(w, line); err != nil {
				return err
			}
		}
		for _, k := range keys {
			// Encode into a []byte so the base64 representation can be zeroed
			// after writing, matching the other format handlers (shell, docker, json)
			// that avoid immutable string copies of secret material.
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(all[k])))
			base64.StdEncoding.Encode(encoded, all[k])
			var writeErr error
			if _, writeErr = fmt.Fprintf(w, "  %s: ", k); writeErr == nil {
				if _, writeErr = w.Write(encoded); writeErr == nil {
					_, writeErr = io.WriteString(w, "\n")
				}
			}
			clear(encoded)
			if writeErr != nil {
				return writeErr
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported export format: %q", format)
	}
}

func (s *Service) ReEncryptAll(ctx context.Context, newRecipients []string) error {
	if s.environment == "" {
		return ErrNoEnvironment
	}
	all, err := s.DecryptAll(ctx)
	if err != nil {
		return err
	}
	defer ClearSecretMap(all)

	newEntries := make(map[string]Entry, len(all))

	for key, val := range all {
		if err := checkContext(ctx); err != nil {
			return err
		}
		// Zero the framed copy of the secret immediately after encryption,
		// matching Set (the source map is cleared by the deferred ClearSecretMap).
		framed := encodeEntryPlaintext(s.environment, key, val)
		encrypted, err := s.enc.Encrypt(framed, newRecipients)
		clear(framed)
		if err != nil {
			return fmt.Errorf("re-encrypt %q: %w", key, err)
		}
		newEntries[key] = Entry{
			Encrypted: encrypted,
		}
	}

	s.vault.Entries = newEntries
	s.vault.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// Marshal returns the vault's current in-memory state encoded as it would be
// written to disk, without touching the filesystem. Exposed separately from
// Save so a caller writing several vaults as one unit (see
// cmd.saveAllVaults) can obtain every vault's bytes before staging any of
// them, keeping the marshal step — which can itself fail, e.g. on a
// pathological entry — out of the write/rename critical section.
func (s *Service) Marshal(environment string) ([]byte, error) {
	if s.environment == "" {
		return nil, ErrNoEnvironment
	}
	// The environment argument names the vault being written (callers iterate
	// over config environments); it must agree with the environment embedded
	// in this service's encrypted entries, otherwise the file-level field and
	// the per-entry bindings would contradict each other on disk.
	if environment != s.environment {
		return nil, fmt.Errorf(
			"marshal environment %q does not match the environment %q this vault's entries are encrypted for",
			environment, s.environment,
		)
	}
	s.vault.Environment = environment
	s.vault.Version = vaultFormatVersion
	data, err := json.MarshalIndent(s.vault, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal vault: %w", err)
	}
	return data, nil
}

func (s *Service) Save(path, environment string) error {
	data, err := s.Marshal(environment)
	if err != nil {
		return err
	}
	// A symlink planted at the vault directory would redirect this save (and
	// its temp file) outside the repository while the command still reports
	// success — e.g. a revoke whose re-encrypted vault never actually lands
	// in git, silently leaving the revoked recipient's encryption in place.
	if err := fileutil.RequireRealDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("vault directory: %w", err)
	}
	return fileutil.AtomicWriteFile(path, data, 0600, ".envseal-tmp-*")
}


const (
	maxVaultFileSize = 50 * 1024 * 1024 // 50 MiB
	maxVaultEntries  = 10000
)

func (s *Service) Load(path string) (err error) {
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrVaultNotFound
		}
		return fmt.Errorf("stat vault: %w", err)
	}
	if !lstatInfo.Mode().IsRegular() {
		return fmt.Errorf("vault path %q is not a regular file", path)
	}
	if lstatInfo.Size() > maxVaultFileSize {
		return fmt.Errorf("vault file exceeds maximum size of %d bytes", maxVaultFileSize)
	}

	//nolint:gosec // G304: path was just Lstat-verified above to be a regular file within size limits; this is not attacker-controlled traversal, it's the configured vault path.
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrVaultNotFound
		}
		return fmt.Errorf("open vault: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat open vault: %w", err)
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return fmt.Errorf("vault file changed between stat and open")
	}

	data, err := io.ReadAll(io.LimitReader(f, maxVaultFileSize+1))
	if err != nil {
		return fmt.Errorf("read vault: %w", err)
	}
	if int64(len(data)) > maxVaultFileSize {
		return fmt.Errorf("vault file exceeds maximum size of %d bytes", maxVaultFileSize)
	}

	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("unmarshal vault: %w", err)
	}

	if v.Version != vaultFormatVersion {
		return fmt.Errorf("unsupported vault version %d (this build supports only version %d)", v.Version, vaultFormatVersion)
	}
	// Vault metadata is attacker-influenced input (the file may come from a
	// shared git repository): validate every field instead of trusting it.
	// Every v4 vault this code writes always satisfies these checks.
	//
	// The environment field is REQUIRED in v4 (Marshal always writes it), so
	// an empty value is itself evidence of tampering — accepting it would let
	// an attacker blank the field to slip a swapped vault file past the fast
	// pre-decryption check below. The per-entry ciphertext binding would still
	// catch the swap at decrypt time; failing here is earlier and clearer.
	if v.Environment == "" {
		return fmt.Errorf("vault file is missing its environment field — v%d vaults always record one; the file may have been tampered with", vaultFormatVersion)
	}
	if err := config.ValidateEnvironmentName(v.Environment); err != nil {
		return fmt.Errorf("vault file contains invalid environment name: %w", err)
	}
	if s.environment != "" && v.Environment != s.environment {
		return fmt.Errorf(
			"vault file belongs to environment %q but %q was requested — if you renamed the environment in config.toml, re-create the vault for the new name; otherwise the file may have been swapped with another environment's vault",
			v.Environment, s.environment,
		)
	}
	if err := validateVaultTimestamp("created_at", v.CreatedAt); err != nil {
		return err
	}
	if err := validateVaultTimestamp("updated_at", v.UpdatedAt); err != nil {
		return err
	}
	if v.Entries == nil {
		v.Entries = make(map[string]Entry)
	}
	if len(v.Entries) > maxVaultEntries {
		return fmt.Errorf("vault contains %d entries, exceeding maximum of %d", len(v.Entries), maxVaultEntries)
	}
	const maxEntrySize = 10 * 1024 * 1024 // 10 MiB per encrypted entry
	for key, entry := range v.Entries {
		if len(key) > maxKeyNameLength {
			return fmt.Errorf("vault contains key name %q exceeding maximum length of %d characters", key, maxKeyNameLength)
		}
		if !validKeyName.MatchString(key) {
			return fmt.Errorf("vault contains invalid key name %q", key)
		}
		if len(entry.Encrypted) > maxEntrySize {
			return fmt.Errorf("vault entry %q encrypted data exceeds maximum size of %d bytes", key, maxEntrySize)
		}
	}

	s.vault = &v
	return nil
}

// validateVaultTimestamp rejects vault timestamp fields that are not valid
// RFC 3339. Save always writes RFC 3339, so any other content means the file
// was hand-edited or tampered with; an unvalidated string here would be
// re-persisted by Save and echoed into error messages. Empty is allowed for
// defensive compatibility (the field is informational only).
func validateVaultTimestamp(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("vault file contains invalid %s timestamp: %w", field, err)
	}
	return nil
}

// hasChanged reports whether plainValue differs from the value currently
// stored under key. Determining this requires decrypting the existing entry
// — there is no shortcut via a stored plaintext hash, since that would
// reintroduce an offline oracle for guessing low-entropy secrets.
func (s *Service) hasChanged(key string, plainValue []byte) bool {
	entry, exists := s.vault.Entries[key]
	if !exists {
		return true
	}
	plaintext, err := s.enc.Decrypt(entry.Encrypted)
	if err != nil {
		return true
	}
	defer clear(plaintext)
	value, err := verifyEntry(s.environment, key, plaintext)
	if err != nil {
		return true
	}
	return !bytes.Equal(value, plainValue)
}

// writeShellEscapedBytes writes s into a POSIX single-quoted context:
// the only character that needs escaping is the single-quote itself.
// Null bytes are dropped (not valid in environment variables).
func writeShellEscapedBytes(w io.Writer, s []byte) error {
	start := 0
	for i, ch := range s {
		switch ch {
		case '\'':
			if i > start {
				if _, err := w.Write(s[start:i]); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, "'\\''"); err != nil {
				return err
			}
			start = i + 1
		case 0:
			if i > start {
				if _, err := w.Write(s[start:i]); err != nil {
					return err
				}
			}
			start = i + 1
		}
	}
	if start < len(s) {
		_, err := w.Write(s[start:])
		return err
	}
	return nil
}

// writeDockerEscapedBytes writes s into a docker env-file double-quoted context.
// Null bytes and raw control characters are dropped.
func writeDockerEscapedBytes(w io.Writer, s []byte) error {
	start := 0
	flush := func(end int) error {
		if end > start {
			_, err := w.Write(s[start:end])
			return err
		}
		return nil
	}
	writeStr := func(i int, esc string) error {
		if err := flush(i); err != nil {
			return err
		}
		_, err := io.WriteString(w, esc)
		return err
	}
	for i, ch := range s {
		switch ch {
		case '\\':
			if err := writeStr(i, `\\`); err != nil {
				return err
			}
			start = i + 1
		case '"':
			if err := writeStr(i, `\"`); err != nil {
				return err
			}
			start = i + 1
		case '\n':
			if err := writeStr(i, `\n`); err != nil {
				return err
			}
			start = i + 1
		case '\r':
			if err := writeStr(i, `\r`); err != nil {
				return err
			}
			start = i + 1
		case '\t':
			if err := writeStr(i, `\t`); err != nil {
				return err
			}
			start = i + 1
		case '$':
			if err := writeStr(i, `\$`); err != nil {
				return err
			}
			start = i + 1
		case '`':
			if err := writeStr(i, "\\`"); err != nil {
				return err
			}
			start = i + 1
		case 0:
			if err := flush(i); err != nil {
				return err
			}
			start = i + 1
		default:
			if ch < 0x20 || ch == 0x7f {
				if err := flush(i); err != nil {
					return err
				}
				start = i + 1
			}
		}
	}
	return flush(len(s))
}

// writeSecretsJSON writes secrets as a JSON object, encoding each value
// directly from []byte without converting to string. Go strings are immutable
// and cannot be zeroed, so a string([]byte) conversion would leave plaintext
// in heap memory until GC. The []byte produced per value is zeroed after writing.
func writeSecretsJSON(w io.Writer, keys []string, all map[string][]byte) error {
	if _, err := io.WriteString(w, "{\n"); err != nil {
		return err
	}
	for i, k := range keys {
		keyJSON, err := json.Marshal(k)
		if err != nil {
			return err
		}
		valJSON := secretToJSONString(all[k])

		// Write each field using w.Write([]byte) so that valJSON is never
		// implicitly converted to a string (fmt.Fprintf("%s", []byte) calls
		// string(b) internally, creating an unzeroable copy of secret material).
		var writeErr error
		if _, writeErr = io.WriteString(w, "  "); writeErr == nil {
			if _, writeErr = w.Write(keyJSON); writeErr == nil {
				if _, writeErr = io.WriteString(w, ": "); writeErr == nil {
					_, writeErr = w.Write(valJSON)
				}
			}
		}
		clear(valJSON)
		if writeErr != nil {
			return writeErr
		}
		suffix := ",\n"
		if i == len(keys)-1 {
			suffix = "\n"
		}
		if _, err := io.WriteString(w, suffix); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "}\n")
	return err
}

// secretToJSONString encodes src as a JSON string literal stored in a []byte
// that the caller must zero with clear() after use. No string conversions are
// performed so no immutable heap copies of the secret value are created.
func secretToJSONString(src []byte) []byte {
	const hexChars = "0123456789abcdef"
	buf := make([]byte, 0, len(src)+2)
	buf = append(buf, '"')
	for _, b := range src {
		switch b {
		case '"':
			buf = append(buf, '\\', '"')
		case '\\':
			buf = append(buf, '\\', '\\')
		case '\n':
			buf = append(buf, '\\', 'n')
		case '\r':
			buf = append(buf, '\\', 'r')
		case '\t':
			buf = append(buf, '\\', 't')
		case '\b':
			buf = append(buf, '\\', 'b')
		case '\f':
			buf = append(buf, '\\', 'f')
		default:
			if b < 0x20 || b == 0x7f {
				buf = append(buf, '\\', 'u', '0', '0', hexChars[b>>4], hexChars[b&0x0f])
			} else {
				buf = append(buf, b)
			}
		}
	}
	buf = append(buf, '"')
	return buf
}
