package envfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Escaping was one-directional before this: quoteIfNeeded turned a quote into
// \" and unquote handed the backslash back. These tests pin both halves
// together, because a round trip is the only property that actually matters.

func TestValuesRoundTripThroughQuoting(t *testing.T) {
	cases := []struct{ name, value string }{
		{"plain", "hunter2"},
		{"spaces", "two words"},
		{"double quote", `He said "hi"`},
		{"backslash", `back\slash`},
		{"backslash before quote", `trailing\"`},
		{"hash", "value # not a comment"},
		{"dollar", "cost $5"},
		{"single quote", "it's"},
		{"tab", "tab\there"},
		{"newline", "line one\nline two"},
		{"PEM block", "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"},
		{"CRLF inside a value", "a\r\nb"},
		{"literal backslash-n", `not\\na newline`},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := unquote(quoteIfNeeded(tc.value, 0))
			if got != tc.value {
				t.Errorf("round trip: got %q, want %q (encoded as %s)",
					got, tc.value, quoteIfNeeded(tc.value, 0))
			}
		})
	}
}

func TestAMultiLineValueIsWrittenOnASingleLine(t *testing.T) {
	// The parser is line-based. A real newline in the file would split the
	// assignment and corrupt everything after it.
	got := quoteIfNeeded("a\nb", 0)
	for _, r := range got {
		if r == '\n' || r == '\r' {
			t.Fatalf("encoded form contains a real line break: %q", got)
		}
	}
	if got != `"a\nb"` {
		t.Errorf("got %s, want %s", got, `"a\nb"`)
	}
}

func TestAMultiLineValueForcesDoubleQuotes(t *testing.T) {
	// Single quotes cannot carry escapes, so a key that was single-quoted has to
	// change style when its value gains a newline — otherwise the \n would be
	// stored literally and read back as two characters.
	got := quoteIfNeeded("a\nb", '\'')
	if got != `"a\nb"` {
		t.Errorf("got %s, want double quotes", got)
	}
}

func TestSingleQuotedValuesAreNotUnescaped(t *testing.T) {
	// POSIX semantics, and what dotenv loaders do: inside single quotes a
	// backslash is just a backslash.
	got, style := unquote(`'a\nb'`)
	if got != `a\nb` {
		t.Errorf("got %q, want the backslash left alone", got)
	}
	if style != '\'' {
		t.Errorf("style = %q", style)
	}
}

func TestDoubleQuotedEscapesAreInterpreted(t *testing.T) {
	// This is the deliberate compatibility change: warden now reads a
	// double-quoted value the way the app's dotenv loader does.
	cases := []struct{ in, want string }{
		{`"a\nb"`, "a\nb"},
		{`"a\r\nb"`, "a\r\nb"},
		{`"a\tb"`, "a\tb"},
		{`"a\"b"`, `a"b`},
		{`"a\\b"`, `a\b`},
		{`"a\\nb"`, `a\nb`}, // escaped backslash then a literal n, NOT a newline
		{`"trailing\\"`, `trailing\`},
	}
	for _, tc := range cases {
		got, _ := unquote(tc.in)
		if got != tc.want {
			t.Errorf("unquote(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnquoteLeavesUnknownEscapesAlone(t *testing.T) {
	// A stray \z is not an escape warden knows. Swallowing the backslash would
	// silently change a value nobody asked it to touch.
	if got, _ := unquote(`"a\zb"`); got != `a\zb` {
		t.Errorf("got %q, want the sequence preserved", got)
	}
}

func TestAMultiLineValueSurvivesSaveAndReload(t *testing.T) {
	const pem = "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("APP_NAME=Warden\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.Set("TLS_KEY", pem)
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	// The file itself must still be four lines: the comment-free original, the
	// new assignment, and a trailing newline.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(splitLines(string(body))); n != 2 {
		t.Errorf("file has %d assignment lines, want 2:\n%s", n, body)
	}

	reopened, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get("TLS_KEY")
	if !ok {
		t.Fatal("TLS_KEY missing after reload")
	}
	if got != pem {
		t.Errorf("got %q, want %q", got, pem)
	}
	if v, _ := reopened.Get("APP_NAME"); v != "Warden" {
		t.Errorf("the neighbouring key was disturbed: %q", v)
	}
}

// splitLines returns the non-empty lines of a file body.
func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
