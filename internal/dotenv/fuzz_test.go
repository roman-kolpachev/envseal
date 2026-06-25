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
