package dotenv

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParse exercises the hand-written byte-level parser with arbitrary
// input. Parse handles untrusted content in two ways: user-edited .env files
// and the stdout of external subprocesses (sops, dotenvx) — neither is
// guaranteed to be well-formed, so the parser must never panic or hang
// regardless of input, only return a value or an error.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"KEY=value",
		"KEY=",
		"=value",
		"KEY=\"unterminated",
		"KEY='unterminated",
		"KEY=\"esc\\x\"",
		"KEY=\"esc\\x1\"",
		"KEY=\"esc\\xzz\"",
		"KEY=\"esc\\q\"",
		"export KEY=value",
		"# comment\nKEY=value",
		"KEY=value\r\nKEY2=value2",
		"KEY=\"multi\nline\"",
		"KEY=\"\\0\\n\\r\\t\\a\\b\\f\\v\\\\\\\"\\!\\$\\`\"",
		strings.Repeat("K=V\n", 20000),
		"KEY=" + strings.Repeat("x", 1<<20),
		"\x00\x01\x02=\x03\x04",
		"KEY=\"" + strings.Repeat("\\x41", 1000) + "\"",
		"KEY = value",
		"  KEY=value  ",
		"KEY==value",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		entries, err := Parse(strings.NewReader(input))
		if err != nil {
			return
		}
		// Round-tripping through Marshal must not panic either, and must
		// itself remain parseable.
		out := Marshal(entries)
		if _, err := Parse(bytes.NewReader(out)); err != nil {
			t.Fatalf("Marshal output failed to re-parse: %v\ninput=%q\nmarshaled=%q", err, input, out)
		}
	})
}

// FuzzMarshalValueCannotAddKeys guards the sealed-mode secrets file and
// `pull`: a vault entry's value is attacker-controllable (anyone with the
// public keys can forge one), so no value may make Marshal's output parse
// back as extra or different keys. For example, "x\nGIT_CONFIG_COUNT=1" must
// not smuggle a variable past the dangerous-name check.
func FuzzMarshalValueCannotAddKeys(f *testing.F) {
	for _, s := range []string{
		"", "x", "x\nGIT_CONFIG_COUNT=1", "x\r\nGIT_CONFIG_COUNT=1", "x\rGIT_CONFIG_COUNT=1",
		"\"\nGIT_CONFIG_COUNT=1\n\"", "'\nB=1\n'", "\\", "x\\", "\\\"", "a\\nB=1",
		"`\nB=1`", "$(B=1)", "# c\nB=1", "export B=1", "\x0bB=1", "\x0cB=1", "\x85B=1",
		" B=1", "\xff\xfe", "\x0aB=1",
	} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if strings.IndexByte(a, 0) >= 0 || strings.IndexByte(b, 0) >= 0 {
			return // Set rejects null bytes; they never reach Marshal.
		}
		in := []Entry{{Key: "A", Value: []byte(a)}, {Key: "B", Value: []byte(b)}}
		out := Marshal(in)
		got, err := Parse(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("re-parse failed: %v\nmarshaled=%q", err, out)
		}
		if len(got) != 2 || got[0].Key != "A" || got[1].Key != "B" {
			keys := make([]string, 0, len(got))
			for _, e := range got {
				keys = append(keys, e.Key)
			}
			t.Fatalf("values changed the key set: got %q\nmarshaled=%q", keys, out)
		}
		if string(got[0].Value) != a || string(got[1].Value) != b {
			t.Fatalf("value not preserved: got %q,%q want %q,%q\nmarshaled=%q", got[0].Value, got[1].Value, a, b, out)
		}
	})
}
