package prompt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates a source file holding exactly raw, with no help from the
// test framework — the byte-for-byte contents are what these tests are about.
func writeFile(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFileReadsTheValue(t *testing.T) {
	got, err := File{Path: writeFile(t, "hunter2")}.AskSecret("DB_PASSWORD", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if got.Expose() != "hunter2" {
		t.Errorf("got %q, want %q", got.Expose(), "hunter2")
	}
}

func TestFileStripsExactlyOneTrailingNewline(t *testing.T) {
	// `cat`-style files end in a newline that is not part of the value. Exactly
	// one comes off: a file ending in two newlines has a genuinely empty last
	// line, and guessing otherwise silently changes the value.
	cases := []struct{ name, raw, want string }{
		{"trailing LF", "hunter2\n", "hunter2"},
		{"trailing CRLF", "hunter2\r\n", "hunter2"},
		{"no trailing newline", "hunter2", "hunter2"},
		{"trailing spaces are kept", "hunter2  \n", "hunter2  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := File{Path: writeFile(t, tc.raw)}.AskSecret("K", "/tmp/.env")
			if err != nil {
				t.Fatal(err)
			}
			if got.Expose() != tc.want {
				t.Errorf("got %q, want %q", got.Expose(), tc.want)
			}
		})
	}
}

func TestFileRefusesAnEmptyFile(t *testing.T) {
	// Same answer as an empty dialog: nothing was supplied, so nothing is written.
	for _, raw := range []string{"", "\n"} {
		_, err := File{Path: writeFile(t, raw)}.AskSecret("K", "/tmp/.env")
		if !errors.Is(err, ErrCancelled) {
			t.Errorf("raw %q: err = %v, want ErrCancelled", raw, err)
		}
	}
}

func TestFileKeepsEmbeddedNewlines(t *testing.T) {
	// A PEM block is most of the reason to read a value from a file at all.
	// envfile escapes the line breaks onto a single stored line, so the value
	// survives rather than splitting the assignment.
	const pem = "-----BEGIN KEY-----\nabc\n-----END KEY-----"
	got, err := File{Path: writeFile(t, pem+"\n")}.AskSecret("TLS_KEY", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if got.Expose() != pem {
		t.Errorf("got %q, want %q", got.Expose(), pem)
	}
}

func TestFileReportsAMissingFile(t *testing.T) {
	_, err := File{Path: filepath.Join(t.TempDir(), "absent.txt")}.AskSecret("K", "/tmp/.env")
	if err == nil {
		t.Fatal("want an error for a missing file")
	}
	if errors.Is(err, ErrCancelled) {
		t.Error("a missing file is an error, not a cancellation — they carry different exit codes")
	}
}

func TestFileErrorsNeverEmbedTheContents(t *testing.T) {
	// The whole point of --from-file is that the value never reaches the caller.
	// An error that quotes the file back would hand it over. A directory is the
	// simplest read failure to provoke.
	dir := t.TempDir()
	_, err := File{Path: dir}.AskSecret("K", "/tmp/.env")
	if err == nil {
		t.Fatal("want an error for an unreadable path")
	}
	if strings.Contains(err.Error(), "cnry") {
		t.Errorf("error leaked contents: %s", err)
	}
}
