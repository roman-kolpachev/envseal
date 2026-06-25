package dotenv

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/roman-kolpachev/envseal/internal/fileutil"
)

const (
	maxFileSize = 10 * 1024 * 1024 // 10 MiB
	maxEntries  = 10000
)

type Entry struct {
	Key   string
	Value []byte
}

// Parse reads a dotenv-format stream and returns key/value pairs.
// The raw input bytes are zeroed before Parse returns, so secret values
// linger only in the returned Entry.Value slices (which callers must zero).
func Parse(r io.Reader) ([]Entry, error) {
	limited := io.LimitReader(r, maxFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		// io.ReadAll returns whatever was read before the failure — that
		// partial buffer can already hold secret material, so wipe it.
		clear(data)
		return nil, err
	}
	if len(data) > maxFileSize {
		clear(data)
		return nil, fmt.Errorf("file exceeds maximum size of %d bytes", maxFileSize)
	}
	defer clear(data)

	var entries []Entry
	n := len(data)
	// Strip UTF-8 BOM if present. Windows tools (including sops when run on
	// Windows) commonly prepend \xef\xbb\xbf; treating it as transparent makes
	// the parser portable across toolchains without requiring callers to strip it.
	i := 0
	if n >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		i = 3
	}

	for i < n {
		// Skip blank lines and inter-entry whitespace.
		for i < n && (data[i] == '\n' || data[i] == '\r' || data[i] == ' ' || data[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		// Skip comment lines.
		if data[i] == '#' {
			for i < n && data[i] != '\n' {
				i++
			}
			continue
		}

		// Locate end of logical line.
		lineEnd := i
		for lineEnd < n && data[lineEnd] != '\n' {
			lineEnd++
		}

		// Trim leading whitespace.
		contentStart := i
		for contentStart < lineEnd && (data[contentStart] == ' ' || data[contentStart] == '\t' || data[contentStart] == '\r') {
			contentStart++
		}
		// Trim trailing whitespace.
		contentEnd := lineEnd
		for contentEnd > contentStart && (data[contentEnd-1] == ' ' || data[contentEnd-1] == '\t' || data[contentEnd-1] == '\r') {
			contentEnd--
		}

		// Strip optional "export " prefix.
		const exportPrefix = "export "
		if contentEnd-contentStart >= len(exportPrefix) && bytes.HasPrefix(data[contentStart:contentEnd], []byte(exportPrefix)) {
			contentStart += len(exportPrefix)
		}

		// Find '='.
		eqPos := -1
		for j := contentStart; j < contentEnd; j++ {
			if data[j] == '=' {
				eqPos = j
				break
			}
		}
		if eqPos == -1 {
			i = lineEnd + 1
			continue
		}

		// Parse key (trim surrounding whitespace, key is not secret).
		keyStart := contentStart
		keyEnd := eqPos
		for keyStart < keyEnd && (data[keyStart] == ' ' || data[keyStart] == '\t') {
			keyStart++
		}
		for keyEnd > keyStart && (data[keyEnd-1] == ' ' || data[keyEnd-1] == '\t') {
			keyEnd--
		}
		if keyStart >= keyEnd {
			i = lineEnd + 1
			continue
		}
		key := string(data[keyStart:keyEnd])

		// Skip leading spaces after '='.
		valStart := eqPos + 1
		for valStart < contentEnd && (data[valStart] == ' ' || data[valStart] == '\t') {
			valStart++
		}

		if len(entries) >= maxEntries {
			zeroEntries(entries)
			return nil, fmt.Errorf("file contains more than %d entries", maxEntries)
		}

		if valStart < contentEnd && (data[valStart] == '"' || data[valStart] == '\'') {
			quote := data[valStart]
			// valStart is the opening quote; start parsing after it.
			value, end, parseErr := readQuotedBytes(data, valStart+1, quote)
			if parseErr != nil {
				zeroEntries(entries)
				return nil, fmt.Errorf("parse value for key %q: %w", key, parseErr)
			}
			entries = append(entries, Entry{Key: key, Value: value})
			i = end
		} else {
			// Unquoted value: copy into an independent slice so defer clear(data) is safe.
			valueCopy := make([]byte, contentEnd-valStart)
			copy(valueCopy, data[valStart:contentEnd])
			entries = append(entries, Entry{Key: key, Value: valueCopy})
			i = lineEnd + 1
		}
	}

	return entries, nil
}

// zeroEntries wipes the secret values of all accumulated entries. Parse calls
// it on every error path after entries have been collected so that partially
// parsed secrets never outlive the error — the caller receives nil and would
// otherwise have no way to clear them.
func zeroEntries(entries []Entry) {
	for i := range entries {
		clear(entries[i].Value)
	}
}

// readQuotedBytes parses a quoted string in data starting at start (after the opening quote).
// On unterminated input, it returns the accumulated content with a nil error — conventional
// dotenv behaviour preserved for backward compatibility.
// The returned slice is an independent allocation; the caller must zero it after use.
func readQuotedBytes(data []byte, start int, quote byte) (_ []byte, _ int, err error) {
	var buf bytes.Buffer
	// Pre-size the buffer so it never reallocates while accumulating secret
	// bytes: a reallocation would strand the previous (smaller) backing array
	// holding a secret prefix that the deferred clear below cannot reach.
	// Decoded output is never longer than its encoded input (every escape
	// sequence shrinks), so the encoded span length is a safe upper bound.
	buf.Grow(quotedSpanLen(data, start, quote))
	defer func() {
		// Zero the buffer's internal storage on all return paths.
		if b := buf.Bytes(); len(b) > 0 {
			clear(b)
		}
	}()

	i := start
	doubleQuote := quote == '"'

	for i < len(data) {
		ch := data[i]
		if ch == quote {
			result := make([]byte, buf.Len())
			copy(result, buf.Bytes())
			return result, i + 1, nil
		}
		if doubleQuote && ch == '\\' && i+1 < len(data) {
			next := data[i+1]
			switch next {
			case 'n':
				buf.WriteByte('\n')
			case 'r':
				buf.WriteByte('\r')
			case 't':
				buf.WriteByte('\t')
			case 'a':
				buf.WriteByte('\a')
			case 'b':
				buf.WriteByte('\b')
			case 'f':
				buf.WriteByte('\f')
			case 'v':
				buf.WriteByte('\v')
			case '0':
				buf.WriteByte(0)
			case '\\':
				buf.WriteByte('\\')
			case '"':
				buf.WriteByte('"')
			case '!':
				buf.WriteByte('!')
			case '$':
				buf.WriteByte('$')
			case '`':
				buf.WriteByte('`')
			case 'x':
				if i+3 < len(data) {
					hi := unhex(data[i+2])
					lo := unhex(data[i+3])
					if hi >= 0 && lo >= 0 {
						// hi, lo are each bounded to [0,15] by unhex (0-9/a-f/A-F
						// only, -1 otherwise, just checked above), so hi<<4|lo is
						// always in [0,255] — safe to narrow to byte.
						//nolint:gosec // G115: bounds proven by the hi>=0 && lo>=0 check above, not visible to static analysis.
						buf.WriteByte(byte(hi<<4 | lo))
						i += 4
						continue
					}
				}
				return nil, i, fmt.Errorf("invalid hex escape \\x at position %d", i)
			default:
				// Reject unknown escape sequences to prevent round-trip inconsistencies.
				return nil, i, fmt.Errorf("unknown escape sequence \\%c in double-quoted value at position %d", rune(next), i)
			}
			i += 2
			continue
		}
		buf.WriteByte(ch)
		i++
	}
	// Unterminated quote: return accumulated content (conventional dotenv behaviour).
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, i, nil
}

// quotedSpanLen returns the number of encoded bytes between start and the
// closing quote (or end of data when the value is unterminated), skipping
// backslash escapes in double-quoted values so an escaped quote does not end
// the scan early. Used to pre-size the decode buffer in readQuotedBytes.
func quotedSpanLen(data []byte, start int, quote byte) int {
	i := start
	doubleQuote := quote == '"'
	for i < len(data) {
		if data[i] == quote {
			return i - start
		}
		if doubleQuote && data[i] == '\\' && i+1 < len(data) {
			i += 2
			continue
		}
		i++
	}
	return i - start
}

// Marshal encodes entries as dotenv format. The internal buffer is zeroed
// before Marshal returns; only the returned []byte holds secret content.
func Marshal(entries []Entry) []byte {
	var buf bytes.Buffer
	// Pre-size to a worst-case upper bound (every value byte escaping to the
	// 4-byte \xNN form, plus quotes, '=', and the trailing newline) so the
	// buffer never reallocates while holding secret material — a grow would
	// strand an unzeroable partial copy in the old backing array.
	size := 0
	for _, e := range entries {
		size += len(e.Key) + 4*len(e.Value) + 4
	}
	buf.Grow(size)
	for _, e := range entries {
		buf.WriteString(e.Key)
		buf.WriteByte('=')
		if needsQuoting(e.Value) {
			buf.WriteByte('"')
			writeEscapedDoubleQuoted(&buf, e.Value)
			buf.WriteByte('"')
		} else {
			buf.Write(e.Value)
		}
		buf.WriteByte('\n')
	}
	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	if b := buf.Bytes(); len(b) > 0 {
		clear(b)
	}
	return result
}

func needsQuoting(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, b := range value {
		if !isSafeUnquoted(b) {
			return true
		}
	}
	return false
}

func isSafeUnquoted(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '-' || b == '_' || b == '.' ||
		b == '/' || b == ':' || b == '+' ||
		b == ',' || b == '@' || b == '%' || b == '='
}

func writeEscapedDoubleQuoted(buf *bytes.Buffer, s []byte) {
	buf.Grow(len(s))
	for _, ch := range s {
		switch ch {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '$':
			buf.WriteString(`\$`)
		case '`':
			buf.WriteString("\\`")
		case '!':
			buf.WriteString(`\!`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\a':
			buf.WriteString(`\a`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\v':
			buf.WriteString(`\v`)
		case 0:
			// drop null bytes
		default:
			if ch < 0x20 || ch == 0x7f {
				fmt.Fprintf(buf, `\x%02x`, ch)
			} else {
				buf.WriteByte(ch)
			}
		}
	}
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}

func MarshalFile(path string, entries []Entry) error {
	data := Marshal(entries)
	defer clear(data)

	// Temp pattern ".env.tmp-*" (not a generic ".envseal-env-*" name): a
	// crash between CreateTemp and the commit rename orphans a temp file
	// holding DECRYPTED SECRETS in the target directory (the project root,
	// for `envseal pull`). Named ".env.tmp-<random>", the orphan is already
	// covered by the protections that exist for plaintext env files — init's
	// ".env.*" .gitignore entry and the pre-commit hook's \.env(\.[^/]+)?$
	// pattern — whereas the old name matched neither, so git would happily
	// commit the plaintext.
	return fileutil.AtomicWriteFile(
		path,
		data,
		0600,
		".env.tmp-*",
	)
}

func ParseFile(path string) (entries []Entry, err error) {
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("path %q is not a regular file", path)
	}

	//nolint:gosec // G304: path was just Lstat-verified above to be a regular file; this is not attacker-controlled traversal.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
	}()

	fdInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open file %s: %w", path, err)
	}
	if !os.SameFile(lstatInfo, fdInfo) {
		return nil, fmt.Errorf("file %q changed between stat and open", path)
	}

	return Parse(f)
}
