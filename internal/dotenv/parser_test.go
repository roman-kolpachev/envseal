package dotenv

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []Entry
		wantErr bool
	}{
		{
			name:  "simple key=value",
			input: "DB_HOST=localhost",
			want:  []Entry{{Key: "DB_HOST", Value: []byte("localhost")}},
		},
		{
			name:  "double quoted value",
			input: `API_KEY="sk-123abc"`,
			want:  []Entry{{Key: "API_KEY", Value: []byte("sk-123abc")}},
		},
		{
			name:  "single quoted value",
			input: `SECRET='my secret'`,
			want:  []Entry{{Key: "SECRET", Value: []byte("my secret")}},
		},
		{
			name:  "empty value",
			input: "EMPTY=",
			want:  []Entry{{Key: "EMPTY", Value: []byte("")}},
		},
		{
			name:  "comment line skipped",
			input: "# comment\nKEY=val",
			want:  []Entry{{Key: "KEY", Value: []byte("val")}},
		},
		{
			name:  "export prefix stripped",
			input: "export DB=localhost",
			want:  []Entry{{Key: "DB", Value: []byte("localhost")}},
		},
		{
			name:  "multiple entries",
			input: "A=1\nB=2\nC=3",
			want:  []Entry{{Key: "A", Value: []byte("1")}, {Key: "B", Value: []byte("2")}, {Key: "C", Value: []byte("3")}},
		},
		{
			name:  "empty lines ignored",
			input: "A=1\n\n\nB=2",
			want:  []Entry{{Key: "A", Value: []byte("1")}, {Key: "B", Value: []byte("2")}},
		},
		{
			name:  "double-quoted multiline value",
			input: "CERT=\"line1\nline2\nline3\"",
			want:  []Entry{{Key: "CERT", Value: []byte("line1\nline2\nline3")}},
		},
		{
			name:  "single-quoted multiline value",
			input: "KEY='first\nsecond\nthird'",
			want:  []Entry{{Key: "KEY", Value: []byte("first\nsecond\nthird")}},
		},
		{
			name:  "multiline with other entries",
			input: "A=1\nCERT=\"-----BEGIN RSA-----\nabc\n-----END RSA-----\"\nB=2",
			want: []Entry{
				{Key: "A", Value: []byte("1")},
				{Key: "CERT", Value: []byte("-----BEGIN RSA-----\nabc\n-----END RSA-----")},
				{Key: "B", Value: []byte("2")},
			},
		},
		{
			name:  "multiline with escaped newlines",
			input: `JSON="{\n  \"key\": \"val\"\n}"`,
			want:  []Entry{{Key: "JSON", Value: []byte("{\n  \"key\": \"val\"\n}")}},
		},
		{
			name:  "multiline preserves inner quotes",
			input: "SQL=\"SELECT *\nFROM users\nWHERE id = 1\"",
			want:  []Entry{{Key: "SQL", Value: []byte("SELECT *\nFROM users\nWHERE id = 1")}},
		},
		{
			name:  "value with equals sign",
			input: "URL=postgres://host:5432/db?sslmode=require",
			want:  []Entry{{Key: "URL", Value: []byte("postgres://host:5432/db?sslmode=require")}},
		},
		{
			name:  "UTF-8 BOM stripped transparently",
			input: "\xef\xbb\xbfFIRST=one\nSECOND=two",
			want:  []Entry{{Key: "FIRST", Value: []byte("one")}, {Key: "SECOND", Value: []byte("two")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i].Key != tt.want[i].Key || string(got[i].Value) != string(tt.want[i].Value) {
					t.Errorf("entry %d: got {%q, %q}, want {%q, %q}",
						i, got[i].Key, got[i].Value, tt.want[i].Key, tt.want[i].Value)
				}
			}
		})
	}
}


func TestMarshal(t *testing.T) {
	entries := []Entry{
		{Key: "DB_HOST", Value: []byte("localhost")},
		{Key: "DB_PORT", Value: []byte("5432")},
	}
	got := string(Marshal(entries))
	want := "DB_HOST=localhost\nDB_PORT=5432\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMarshalRoundtrip(t *testing.T) {
	original := "DB_HOST=localhost\nDB_PORT=5432\n"
	entries, err := Parse(strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	got := string(Marshal(entries))
	if got != original {
		t.Errorf("roundtrip failed: got %q, want %q", got, original)
	}
}

func TestMarshalMultiline(t *testing.T) {
	entries := []Entry{
		{Key: "SIMPLE", Value: []byte("hello")},
		{Key: "CERT", Value: []byte("line1\nline2\nline3")},
	}
	got := string(Marshal(entries))
	want := "SIMPLE=hello\nCERT=\"line1\\nline2\\nline3\"\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestMarshal_SingleQuotesForLiteralValues: the sealed secrets file and
// `pull` output are read by other parsers (Node dotenv, dotenv-expand,
// python-dotenv, a shell `source`). They disagree on backslash escapes inside
// double quotes, but all read single-quoted text as-is. So any value that
// single quotes can hold for all of them is written in single quotes.
func TestMarshal_SingleQuotesForLiteralValues(t *testing.T) {
	cases := map[string]string{
		`Passw0rd!`:       `'Passw0rd!'`,
		"a\tb":            "'a\tb'",
		`say "hi"`:        `'say "hi"'`,
		"a`id`b":          "'a`id`b'",
		`C:\path\to`:      `'C:\path\to'`,
		`abc #notcomment`: `'abc #notcomment'`,
		`  padded  `:      `'  padded  '`,
		`{"k": [1, 2]}`:   `'{"k": [1, 2]}'`,
		`also simple`:     `'also simple'`,
		`пароль✓`:         `'пароль✓'`,
	}
	for value, want := range cases {
		got := string(Marshal([]Entry{{Key: "K", Value: []byte(value)}}))
		if got != "K="+want+"\n" {
			t.Errorf("Marshal(%q) = %q, want %q", value, got, "K="+want+"\n")
		}
	}
}

// TestMarshal_DoubleQuotesWhenSingleQuotesCannot: values single quotes cannot
// carry for every parser keep the escaped double-quoted form: a single quote,
// control characters other than tab, backslash runs python-dotenv would
// decode inside single quotes (`\\`, or a trailing `\`), and `$`, which
// dotenv-expand would expand inside single quotes but reads as plain text
// when written as \$. A `!` is no longer escaped.
func TestMarshal_DoubleQuotesWhenSingleQuotesCannot(t *testing.T) {
	cases := map[string]string{
		`it's`:         `"it's"`,
		`it's!`:        `"it's!"`,
		"line1\nline2": `"line1\nline2"`,
		"a\rb":         `"a\rb"`,
		`a\\b`:         `"a\\\\b"`,
		`end\`:         `"end\\"`,
		``:             `""`,
		`Pa$$w0rd!`:    `"Pa\$\$w0rd!"`,
		`x${HOME}y`:    `"x\${HOME}y"`,
	}
	for value, want := range cases {
		got := string(Marshal([]Entry{{Key: "K", Value: []byte(value)}}))
		if got != "K="+want+"\n" {
			t.Errorf("Marshal(%q) = %q, want %q", value, got, "K="+want+"\n")
		}
	}
}

// TestMarshal_QuotingRoundTrips: every form Marshal picks must parse back to
// the exact value with envseal's own parser (`pull` then `sync`).
func TestMarshal_QuotingRoundTrips(t *testing.T) {
	values := []string{
		`plain`, `Pa$$w0rd!`, `x${HOME}y`, `say "hi"`, "a`id`b", `C:\path\to`,
		`abc #notcomment`, `  padded  `, `{"k": [1, 2]}`, `it's`, "line1\nline2",
		"a\tb", `a\\b`, `end\`, ``, `a\nb`, `'`, `"`, `\`, `\'`, `'\`, `$`, `#`, ` `,
		"it's \"both\"", `пароль✓`, `a=b==`,
	}
	for _, v := range values {
		out := Marshal([]Entry{{Key: "K", Value: []byte(v)}, {Key: "NEXT", Value: []byte("x")}})
		got, err := Parse(strings.NewReader(string(out)))
		if err != nil {
			t.Fatalf("Parse(Marshal(%q)) failed: %v\nmarshaled=%q", v, err, out)
		}
		if len(got) != 2 || got[0].Key != "K" || string(got[0].Value) != v || got[1].Key != "NEXT" {
			t.Errorf("round trip of %q failed\nmarshaled=%q\nparsed=%+v", v, out, got)
		}
	}
}

func TestMultilineRoundtrip(t *testing.T) {
	entries := []Entry{
		{Key: "A", Value: []byte("simple")},
		{Key: "CERT", Value: []byte("-----BEGIN RSA-----\nabc\n-----END RSA-----")},
		{Key: "B", Value: []byte("also simple")},
	}
	marshaled := Marshal(entries)
	parsed, err := Parse(strings.NewReader(string(marshaled)))
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != len(entries) {
		t.Fatalf("roundtrip: got %d entries, want %d", len(parsed), len(entries))
	}
	for i := range entries {
		if parsed[i].Key != entries[i].Key || string(parsed[i].Value) != string(entries[i].Value) {
			t.Errorf("entry %d: got {%q, %q}, want {%q, %q}",
				i, parsed[i].Key, parsed[i].Value, entries[i].Key, entries[i].Value)
		}
	}
}

func TestParse_EmptyKeySkipped(t *testing.T) {
	input := "=value\nGOOD=yes\n"
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (empty key should be skipped)", len(entries))
	}
	if entries[0].Key != "GOOD" {
		t.Errorf("got key %q, want GOOD", entries[0].Key)
	}
}

func TestParse_UnterminatedQuote(t *testing.T) {
	input := `KEY="unterminated`
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if string(entries[0].Value) != "unterminated" {
		t.Errorf("got %q, want %q", entries[0].Value, "unterminated")
	}
}

func TestParse_UnknownEscapeInDoubleQuotes(t *testing.T) {
	// Unknown escape sequences are rejected to prevent round-trip value
	// inconsistencies across different consumers (shells, docker, etc.).
	input := `KEY="hello\qworld"`
	_, err := Parse(strings.NewReader(input))
	if err == nil {
		t.Fatal("expected error for unknown escape sequence \\q, got nil")
	}
}

func TestParse_CarriageReturnEscape(t *testing.T) {
	input := `KEY="line1\rline2"`
	entries, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if string(entries[0].Value) != "line1\rline2" {
		t.Errorf("got %q, want %q", entries[0].Value, "line1\rline2")
	}
}

func TestMarshalFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.env"

	entries := []Entry{
		{Key: "HOST", Value: []byte("localhost")},
	}
	err := MarshalFile(path, entries)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Key != "HOST" || string(got[0].Value) != "localhost" {
		t.Errorf("got %+v, want HOST=localhost", got[0])
	}
}
