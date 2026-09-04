package envfile

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// A key is concatenated with "=" and the value to build a line, so the key is
// itself a write primitive: a name carrying a newline does not produce one
// malformed assignment, it produces two well-formed ones. Because Get resolves
// a duplicated key to its last assignment, the injected line silently wins over
// the real one above it.
func TestValidateKeyRejectsNamesThatCouldWriteALine(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"newline starts a second assignment", "Z\nDB_PASSWORD"},
		{"carriage return does the same on CRLF files", "Z\rDB_PASSWORD"},
		{"an equals sign splits the assignment", "A=B"},
		{"a leading digit is not a variable name", "9LIVES"},
		{"a space is not part of a name", "MY KEY"},
		{"a quote can escape the value's quoting", `K"`},
		{"empty is not a name", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateKey(tc.key); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ValidateKey(%q) = %v, want ErrInvalidKey", tc.key, err)
			}
		})
	}
}

func TestValidateKeyAcceptsOrdinaryNames(t *testing.T) {
	for _, key := range []string{"APP_NAME", "_PRIVATE", "DB2_HOST", "A"} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", key, err)
		}
	}
}

// The guarantee that makes the rule easy to reason about: warden cannot write a
// line it would refuse to read back.
func TestSetRefusesAnInjectingKeyAndLeavesTheFileAlone(t *testing.T) {
	path := write(t, ".env", "DB_PASSWORD=the-real-one\n")
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Set("Z\nDB_PASSWORD", "injected"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Set = %v, want ErrInvalidKey", err)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); strings.Contains(got, "injected") {
		t.Errorf("the refused key still changed the file: %q", got)
	}
}
