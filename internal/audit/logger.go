package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/roman-kolpachev/envseal/internal/fileutil"
)

type Event struct {
	Timestamp string   `json:"timestamp"`
	Action    string   `json:"action"`
	Actor     string   `json:"actor,omitempty"`
	Keys      []string `json:"keys,omitempty"`
	Target    string   `json:"target,omitempty"`
	Message   string   `json:"message,omitempty"`
	PrevHash  string   `json:"prev_hash,omitempty"`
}

type Logger struct {
	path     string
	mu       sync.Mutex
	lastHash string
}

func NewLogger(path string) *Logger {
	return &Logger{path: path}
}

func (l *Logger) Log(event Event) (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Ensure parent directory exists before anything else below — including
	// the lock acquisition, which itself needs the directory to already be
	// there — since it may be absent on a freshly-cloned repo where
	// .envseal/audit.log is in .gitignore and was never committed.
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return fmt.Errorf("create audit log directory: %w", err)
	}
	// MkdirAll silently accepts a pre-planted symlink at the path. The
	// file-level Lstat/SameFile checks below defend audit.log itself, but a
	// symlinked parent directory would relocate the entire log (and its
	// .lock): events would accumulate outside the repository and the
	// committed audit trail would silently stop advancing.
	if err := fileutil.RequireRealDir(filepath.Dir(l.path)); err != nil {
		return fmt.Errorf("audit log directory: %w", err)
	}

	// l.mu only guards against concurrent goroutines within this process —
	// it does nothing against a second envseal invocation doing the same
	// thing at the same time, which is routine: get/export/pull all log an
	// event after requireDeps has already released the vault lock (see
	// cmd/root.go), so concurrent read-only commands (or one of those
	// racing a mutating command's own log call after it's done writing)
	// can call Log() with no cross-process synchronization at all otherwise.
	// Without this lock, two processes can both read the same "last hash"
	// via readLastLineHash below before either has appended, then both
	// write a line claiming that same PrevHash — only one of them is
	// actually right, so the chain-integrity check in Recent later reports
	// "the audit log may have been tampered with" for an event that was
	// perfectly ordinary concurrent use. A security feature that cries wolf
	// under normal operation trains operators to ignore it, which is worse
	// than not having it. This is a separate lock file from the vault lock
	// (.envseal/lock, cmd/root.go's requireDeps): that one is intentionally
	// held for a mutating command's entire remaining lifetime, which would
	// be a needless bottleneck here — this one only needs to be held for
	// the read-hash-then-append critical section below.
	auditLock, lockErr := fileutil.Lock(l.path + ".lock")
	if lockErr != nil {
		return fmt.Errorf("acquire audit log lock: %w", lockErr)
	}
	defer func() {
		if cerr := auditLock.Close(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("release audit log lock: %w", cerr))
		}
	}()

	// A lock held across process lifetimes (see above) means l.lastHash —
	// cached from an earlier Log call in this same process — can no longer
	// be trusted as "the current chain head": another process may have
	// appended since. Force the fresh read below on every call rather than
	// only when empty.
	l.lastHash = ""

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// Save pre-open lstat so we can detect file-swap attacks after opening
	// (same pattern used by vault.Load, keyring.LoadFromFile, config.Load, etc.).
	var preLstat os.FileInfo
	if info, statErr := os.Lstat(l.path); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("audit log path %q is not a regular file", l.path)
		}
		if info.Size() > maxAuditLogSize {
			return fmt.Errorf("audit log %q exceeds maximum size of %d bytes — rotate or truncate the file", l.path, maxAuditLogSize)
		}
		preLstat = info
	}

	if l.lastHash == "" {
		hash, hashErr := l.readLastLineHash()
		if hashErr != nil {
			return fmt.Errorf("read audit chain: %w", hashErr)
		}
		l.lastHash = hash
	}
	event.PrevHash = l.lastHash

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}

	// Enforce the per-line size cap BEFORE hashing and writing: a line larger
	// than the scanner token limit would make Recent fail for the whole log
	// and block every future append at readLastLineHash. Truncate the Keys
	// list (recording the omission in Message) rather than dropping the event.
	if len(data) > maxEventLineSize {
		event = truncateEventKeys(event, maxEventLineSize)
		data, err = json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal truncated audit event: %w", err)
		}
		if len(data) > maxEventLineSize {
			return fmt.Errorf("%w: %d bytes after truncation (limit %d)", ErrEventTooLarge, len(data), maxEventLineSize)
		}
	}

	// Compute the new chain head but do NOT advance l.lastHash yet: if any
	// step below fails (directory creation, open, stat checks, write), the
	// line never reaches the log, and advancing the in-memory hash would make
	// the next successfully written event carry a PrevHash pointing at a
	// nonexistent line — falsely tripping the chain-integrity check forever.
	newHash := hashLine(data)
	data = append(data, '\n')

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat audit log: %w", err)
	}
	if !fdInfo.Mode().IsRegular() {
		return fmt.Errorf("audit log path %q is not a regular file", l.path)
	}
	if preLstat != nil {
		// File existed before open: compare pre-open inode with fd inode to detect
		// file-swap attacks (rename-based replacement bypasses a post-open lstat check
		// because both pre- and post-open lstat would see the same new inode).
		if !os.SameFile(preLstat, fdInfo) {
			return fmt.Errorf("audit log %q was replaced between stat and open", l.path)
		}
	} else {
		// File was newly created by the open above: a post-open lstat detects any
		// symlink that was placed at the path in the race window before the open.
		postLstat, postErr := os.Lstat(l.path)
		if postErr != nil {
			return fmt.Errorf("stat audit log path after open: %w", postErr)
		}
		if !os.SameFile(postLstat, fdInfo) {
			return fmt.Errorf("audit log path %q is a symlink or was replaced", l.path)
		}
	}

	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	l.lastHash = newHash
	return nil
}

const (
	maxAuditLogSize = 100 * 1024 * 1024 // 100 MiB
	maxRecentEvents = 1000

	// maxEventLineSize is the maximum size of a single marshaled audit event
	// line. It MUST NOT exceed scannerMaxTokenSize: Recent and
	// readLastLineHash read the log with a bufio.Scanner capped at that
	// token size, so any line Log writes beyond it would make the entire
	// audit history unreadable (bufio.ErrTooLong) and permanently block all
	// subsequent appends — a self-inflicted denial of service on the audit
	// trail triggerable by one legitimate bulk operation (e.g. a sync
	// touching thousands of keys).
	maxEventLineSize = 1024 * 1024

	// scannerMaxTokenSize is the bufio.Scanner token limit shared by Recent
	// and readLastLineHash. Kept as a named constant so the invariant
	// maxEventLineSize <= scannerMaxTokenSize is visible and enforced below.
	scannerMaxTokenSize = 1024 * 1024

	scannerInitialBufSize = 64 * 1024
)

// ErrEventTooLarge indicates that an audit event exceeds maxEventLineSize
// even after its Keys list has been truncated away entirely.
var ErrEventTooLarge = errors.New("audit event exceeds maximum size")

// Compile-time guard: an event line Log accepts must always be readable back
// by the scanner used in Recent/readLastLineHash.
var _ [scannerMaxTokenSize - maxEventLineSize]struct{}

// truncateEventKeys returns a copy of event whose Keys list has been shortened
// until the marshaled JSON line fits within limit. The omission is recorded in
// the Message field so the loss of detail is visible in the log itself rather
// than silent. If even an event with no keys does not fit (oversized Message),
// the zero-keys variant is returned and the caller's size re-check reports it.
func truncateEventKeys(event Event, limit int) Event {
	total := len(event.Keys)
	baseMessage := event.Message
	n := total / 2
	for {
		candidate := event
		candidate.Keys = event.Keys[:n]
		candidate.Message = strings.TrimSpace(fmt.Sprintf(
			"%s [audit: %d of %d keys omitted to fit the %d-byte event size limit]",
			baseMessage, total-n, total, limit,
		))
		data, err := json.Marshal(candidate)
		if err == nil && len(data) <= limit {
			return candidate
		}
		if n == 0 {
			return candidate
		}
		n /= 2
	}
}

func (l *Logger) Recent(n int) (_ []Event, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n <= 0 {
		n = 100
	}
	if n > maxRecentEvents {
		n = maxRecentEvents
	}

	lstatInfo, statErr := os.Lstat(l.path)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, statErr
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("audit log path %q is not a regular file", l.path)
	}
	// Mirror the size cap enforced by Log: reading an unbounded (possibly
	// attacker-inflated) log file into memory is a denial-of-service vector.
	if lstatInfo.Size() > maxAuditLogSize {
		return nil, fmt.Errorf("audit log %q exceeds maximum size of %d bytes — rotate or truncate the file", l.path, maxAuditLogSize)
	}

	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open audit log: %w", err)
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return nil, fmt.Errorf("audit log changed between stat and open")
	}

	// Serialize with concurrent appenders: Log holds this same lock across its
	// read-hash-then-append critical section, so acquiring it here guarantees
	// the scan below never observes a partially written last line. Without it,
	// a read racing an in-flight append can see a torn line and report it as a
	// "corrupted entry" or a broken hash chain — a false tamper alarm, which
	// (per Log's own doc comment) trains operators to ignore the integrity
	// check exactly when it matters. The lock is acquired only after the log
	// file is known to exist (the Lstat above), so its parent directory exists
	// too, and it is released before this function returns. If acquisition
	// fails (e.g. a read-only checkout where the .lock file cannot be
	// created), the read still proceeds — refusing to display history would
	// be a worse failure than the rare torn-read warning — but the failure is
	// surfaced to the caller as a joined non-fatal warning rather than
	// swallowed, matching how corruption and chain breaks are reported below.
	var lockWarn error
	if auditLock, lockErr := fileutil.Lock(l.path + ".lock"); lockErr == nil {
		defer func() {
			if cerr := auditLock.Close(); cerr != nil {
				err = errors.Join(err, fmt.Errorf("release audit log lock: %w", cerr))
			}
		}()
	} else {
		lockWarn = fmt.Errorf("could not acquire audit log lock (reading without it; a concurrent write may appear as a transient corrupted entry): %w", lockErr)
	}

	type indexedEvent struct {
		event Event
		hash  string
	}

	var all []indexedEvent
	skipped := 0
	prevHash := ""
	chainBroken := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, scannerInitialBufSize), scannerMaxTokenSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			skipped++
			prevHash = ""
			continue
		}
		if e.PrevHash != "" && prevHash != "" && e.PrevHash != prevHash {
			chainBroken = true
		}
		lineHash := hashLine(line)
		all = append(all, indexedEvent{event: e, hash: lineHash})
		prevHash = lineHash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	start := 0
	if len(all) > n {
		start = len(all) - n
	}
	events := make([]Event, 0, len(all)-start)
	for _, ie := range all[start:] {
		events = append(events, ie.event)
	}

	var errs []error
	if lockWarn != nil {
		errs = append(errs, lockWarn)
	}
	if skipped > 0 {
		noun := "entries"
		if skipped == 1 {
			noun = "entry"
		}
		errs = append(errs, fmt.Errorf("audit log contains %d corrupted %s", skipped, noun))
	}
	if chainBroken {
		errs = append(errs, fmt.Errorf("audit log hash chain is broken — log may have been tampered with"))
	}
	return events, errors.Join(errs...)
}

// hashLine returns the SHA-256 hex digest of a raw log line and is used to
// build a forward hash chain across audit entries.
//
// Threat model: the chain detects accidental log corruption and naive line
// deletion. It does NOT prevent deliberate forgery by anyone who can write to
// the log file — they can rewrite all entries and recompute a valid chain from
// scratch because the hash is unkeyed. Authenticity (tamper-evidence against
// a privileged attacker) would require an HMAC with a key stored outside the
// log file, which is not implemented here.
func hashLine(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (l *Logger) readLastLineHash() (_ string, err error) {
	lstatInfo, err := os.Lstat(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	if !lstatInfo.Mode().IsRegular() {
		return "", fmt.Errorf("audit log path %q is not a regular file", l.path)
	}

	f, err := os.Open(l.path)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return "", fmt.Errorf("audit log %q was replaced between stat and open", l.path)
	}

	var lastLine []byte
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, scannerInitialBufSize), scannerMaxTokenSize)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) > 0 {
			lastLine = append(lastLine[:0], line...)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if len(lastLine) == 0 {
		return "", nil
	}
	return hashLine(lastLine), nil
}
