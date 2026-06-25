package ui

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"
)

func Success(w io.Writer, msg string) error {
	_, err := fmt.Fprintf(w, "✓ %s\n", msg)
	return err
}

func Error(w io.Writer, msg string) error {
	_, err := fmt.Fprintf(w, "✗ %s\n", msg)
	return err
}

func Info(w io.Writer, msg string) error {
	_, err := fmt.Fprintf(w, "ℹ %s\n", msg)
	return err
}

func Warn(w io.Writer, msg string) error {
	_, err := fmt.Fprintf(w, "⚠ %s\n", msg)
	return err
}

func Table(w io.Writer, headers []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(headers, "\t")); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func KeyValue(w io.Writer, key, value string) error {
	_, err := fmt.Fprintf(w, "  %s: %s\n", key, value)
	return err
}

func Plural(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// SanitizeMultiline sanitizes each line of s for terminal output while
// preserving line breaks. Use for multi-line error messages that may embed
// content from untrusted sources (config files, CLI flag names echoed by
// cobra, file paths) which could otherwise inject terminal escape sequences.
func SanitizeMultiline(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = SanitizeForTerminal(line)
	}
	return strings.Join(lines, "\n")
}

func SanitizeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		// C1 control characters (U+0080–U+009F) include CSI (U+009B) and
		// OSC (U+009D), which some terminals honor as escape-sequence
		// introducers exactly like ESC — strip them as well.
		if r >= 0x80 && r <= 0x9f {
			continue
		}
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
