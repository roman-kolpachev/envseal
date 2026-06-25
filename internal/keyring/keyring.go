package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"filippo.io/age"
	"github.com/roman-kolpachev/envseal/internal/fileutil"
)

type Identity struct {
	PublicKey string
	Recipient age.Recipient
	Identity  age.Identity
}

func (id *Identity) String() string {
	if id == nil {
		return "Identity{<nil>}"
	}
	return fmt.Sprintf("Identity{PublicKey:%s}", id.PublicKey)
}

func (id *Identity) GoString() string {
	if id == nil {
		return "(*keyring.Identity)(nil)"
	}
	return fmt.Sprintf("keyring.Identity{PublicKey:%q}", id.PublicKey)
}

func (id *Identity) Format(f fmt.State, verb rune) {
	// fmt.Formatter has no error return; a write failure here means the
	// underlying fmt.State is already broken, which the caller (not this
	// method) is responsible for surfacing.
	if verb == 'v' && f.Flag('#') {
		_, _ = fmt.Fprint(f, id.GoString())
		return
	}
	_, _ = fmt.Fprint(f, id.String())
}

func Generate() (*Identity, error) {
	k, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return &Identity{
		PublicKey: k.Recipient().String(),
		Recipient: k.Recipient(),
		Identity:  k,
	}, nil
}

func SaveToFile(id *Identity, path string) error {
	x25519, ok := id.Identity.(*age.X25519Identity)
	if !ok {
		return fmt.Errorf("identity is not an X25519 identity")
	}
	// Refuse to write the private key through a symlinked directory. `init`
	// performs this check itself, but SaveToFile is also reached via `keygen`
	// (which creates .envseal with MkdirAll — silently a no-op if a symlink
	// was pre-planted at that path) and `rotate` (which writes keys.new into
	// a directory that may have been replaced since init). Enforcing it here,
	// at the lowest level, covers every present and future caller: a symlink
	// at the parent directory would silently redirect the key file — and its
	// "keys.*" temp file — into an attacker-chosen location.
	if err := fileutil.RequireRealDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("key directory (refusing to write private key): %w", err)
	}
	// Derive the key string at save time only — avoids keeping a persistent
	// string copy of the private key material alive in the Identity struct.
	// The intermediate string is zeroed immediately after the writable []byte
	// copy is made (age builds it freshly on every call, so no other live
	// reference aliases it — the same contract zeroString relies on at every
	// other call site in this package), leaving the wiped buffer below as the
	// only copy of the key material this function created.
	keyStr := x25519.String()
	// Build the file contents in a single exact-capacity allocation. The naive
	// append([]byte(keyStr), '\n') can reallocate (cap of a []byte(string)
	// conversion is not guaranteed to exceed its length), which would strand an
	// unzeroed intermediate copy of the private key in heap memory that the
	// deferred clear below could never reach.
	data := make([]byte, 0, len(keyStr)+1)
	data = append(data, keyStr...)
	data = append(data, '\n')
	zeroString(keyStr)
	defer clear(data)
	// Temp pattern "keys.*" (not a generic ".envseal-key-*" name): a crash
	// between CreateTemp and the commit rename orphans a temp file holding
	// this PRIVATE KEY. Named "keys.<random>", the orphan is already covered
	// by the protections that exist for key files — init's ".envseal/keys.*"
	// .gitignore entry and the pre-commit hook's keys(\.[^/]*)?$ pattern —
	// whereas the old name matched neither, so git would happily commit it.
	if err := fileutil.AtomicWriteFile(path, data, 0600, "keys.*"); err != nil {
		return err
	}
	// On Windows, explicitly restrict the DACL so the key file is not
	// readable by BUILTIN\Users when the project lives outside %USERPROFILE%.
	return secureKeyFile(path)
}

const maxKeyFileSize = 4096

func LoadFromFile(path string) (_ *Identity, err error) {
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	if lstatInfo.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("key file %s exceeds maximum size of %d bytes", path, maxKeyFileSize)
	}
	if runtime.GOOS != "windows" && lstatInfo.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("key file %s has too open permissions %o — run: chmod 600 %s", path, lstatInfo.Mode().Perm(), path)
	}
	if err := checkKeyFileOwnership(path); err != nil {
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}

	//nolint:gosec // G304: path was just Lstat-verified above (regular file, size limit, perms, ownership); this is not attacker-controlled traversal.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open key file: %w", err)
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return nil, fmt.Errorf("key file %s changed between stat and open", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	if int64(len(data)) > maxKeyFileSize {
		clear(data)
		return nil, fmt.Errorf("key file %s exceeds maximum size of %d bytes", path, maxKeyFileSize)
	}

	sub := bytes.TrimSpace(data)
	trimmed := make([]byte, len(sub))
	copy(trimmed, sub)
	clear(data)
	return parseIdentity(trimmed)
}

func LoadFromEnv(envVar string) (*Identity, error) {
	val := os.Getenv(envVar)
	if val == "" {
		return nil, fmt.Errorf("env var %s is empty", envVar)
	}
	// Unsetenv MUST run before either zeroString(val) call below: val's
	// backing bytes alias the process's real environment block (same hazard
	// runner.clearEnvSlice's callers guard against with strings.Clone), so
	// zeroing it while envVar is still live would corrupt this process's own
	// environment. Unsetenv removes envVar's entry first, so nothing —
	// including this process — reads val's backing bytes through the
	// environment again; zeroing afterward only scrubs an otherwise-dead copy.
	// Do not reorder these two calls.
	if err := os.Unsetenv(envVar); err != nil {
		return nil, fmt.Errorf("unset %s from environment: %w", envVar, err)
	}
	if len(val) > maxKeyFileSize {
		zeroString(val)
		return nil, fmt.Errorf("env var %s exceeds maximum key size of %d bytes", envVar, maxKeyFileSize)
	}
	// zeroString mutates val's backing bytes, so trim first and read the key
	// out of the resulting []byte copy before wiping the original string.
	trimmed := []byte(strings.TrimSpace(val))
	zeroString(val)
	return parseIdentity(trimmed)
}

func ParseRecipient(pubkey string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(pubkey)
	if err != nil {
		return nil, fmt.Errorf("parse recipient: %w", err)
	}
	return r, nil
}

const maxDiscoverDepth = 20

func Discover(dir string) (*Identity, error) {
	envVal := os.Getenv("ENVSEAL_KEY")
	if envVal != "" {
		// Unsetenv MUST run before either zeroString(envVal) call below — see
		// the identical ordering requirement documented in LoadFromEnv above.
		if err := os.Unsetenv("ENVSEAL_KEY"); err != nil {
			return nil, fmt.Errorf("unset ENVSEAL_KEY from environment: %w", err)
		}
		if len(envVal) > maxKeyFileSize {
			zeroString(envVal)
			return nil, fmt.Errorf("ENVSEAL_KEY env var exceeds maximum key size of %d bytes", maxKeyFileSize)
		}
		// zeroString mutates envVal's backing bytes, so trim first and read the
		// key out of the resulting []byte copy before wiping the original string.
		trimmed := []byte(strings.TrimSpace(envVal))
		zeroString(envVal)
		id, err := parseIdentity(trimmed)
		if err != nil {
			return nil, fmt.Errorf("ENVSEAL_KEY env var contains an invalid age key: %w", err)
		}
		return id, nil
	}

	current := dir
	for depth := 0; depth < maxDiscoverDepth; depth++ {
		path := filepath.Join(current, ".envseal", "keys")
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("key file %s is not a regular file — refusing to read for security", path)
			}
			return LoadFromFile(path)
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return nil, fmt.Errorf("no private key found — set ENVSEAL_KEY env var or run `envseal init`")
}

// zeroString overwrites a Go string's backing bytes with zeros to minimize
// the window during which secret material (a private key read from a file,
// an env var, or a string([]byte) conversion) is recoverable from a heap
// dump. This is only safe for strings that are not literals and are not
// aliased by other live references the caller still needs — every call site
// in this package satisfies that: the string is either the direct result of
// string([]byte) (which always allocates a fresh backing array) or the raw
// value of os.Getenv for a variable that has just been unset and whose
// (already-copied) trimmed contents are what callers actually use from here
// on. This mirrors the pattern in runner.clearEnvSlice.
func zeroString(s string) {
	if n := len(s); n > 0 {
		//nolint:gosec // G103: audited — see doc comment above; required to zero secret key material, which Go strings otherwise can never scrub from heap.
		clear(unsafe.Slice(unsafe.StringData(s), n))
	}
}

func parseIdentity(key []byte) (*Identity, error) {
	keyStr := string(key)
	k, err := age.ParseX25519Identity(keyStr)
	zeroString(keyStr)
	clear(key)
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	return &Identity{
		PublicKey: k.Recipient().String(),
		Recipient: k.Recipient(),
		Identity:  k,
	}, nil
}
