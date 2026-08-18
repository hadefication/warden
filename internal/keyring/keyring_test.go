package keyring

import (
	"errors"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/secret"
)

// recorder captures what a backend would have executed.
type recorder struct {
	name  string
	args  []string
	stdin string
	out   []byte
	err   error
}

func (r *recorder) run(name, stdin string, args ...string) ([]byte, error) {
	r.name, r.stdin, r.args = name, stdin, args
	return r.out, r.err
}

// The master key must never reach argv: ps is world-readable. This is the
// reason the Runner seam exists at all.
func TestSecuritySetPassesTheValueOnStdinAndNeverInArgv(t *testing.T) {
	r := &recorder{}
	k := Security{Run: r.run}

	if err := k.Set(secret.Secret("master-key-marker")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, a := range r.args {
		if strings.Contains(a, "master-key-marker") {
			t.Fatalf("LEAK: the master key appeared in argv: %v", r.args)
		}
	}
	// security asks twice; a single line leaves the retype reading EOF and the
	// item is silently created empty.
	if r.stdin != "master-key-marker\nmaster-key-marker\n" {
		t.Errorf("stdin = %q, want the value twice", r.stdin)
	}
	if r.name != "security" {
		t.Errorf("name = %q, want security", r.name)
	}
	want := []string{"add-generic-password", "-s", "warden", "-a", "vault-master", "-U", "-w"}
	if strings.Join(r.args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", r.args, want)
	}
}

func TestSecurityGetTrimsTheTrailingNewline(t *testing.T) {
	r := &recorder{out: []byte("master-key-marker\n")}
	got, err := Security{Run: r.run}.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expose() != "master-key-marker" {
		t.Errorf("Get = %q, want the value without its newline", got.Expose())
	}
}

func TestSecurityGetReportsNotFound(t *testing.T) {
	r := &recorder{err: errors.New("exit status 44")}
	if _, err := (Security{Run: r.run}).Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestSecretToolSetPassesTheValueOnStdinOnce(t *testing.T) {
	r := &recorder{}
	if err := (SecretTool{Run: r.run}).Set(secret.Secret("master-key-marker")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, a := range r.args {
		if strings.Contains(a, "master-key-marker") {
			t.Fatalf("LEAK: the master key appeared in argv: %v", r.args)
		}
	}
	// secret-tool store reads the secret from stdin exactly once.
	if r.stdin != "master-key-marker" {
		t.Errorf("stdin = %q, want the value once with no newline", r.stdin)
	}
	want := []string{"store", "--label=warden", "service", "warden", "account", "vault-master"}
	if strings.Join(r.args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", r.args, want)
	}
}

func TestSecretToolGetTreatsEmptyOutputAsNotFound(t *testing.T) {
	r := &recorder{out: []byte("")}
	if _, err := (SecretTool{Run: r.run}).Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestUnavailableRefusesEverything(t *testing.T) {
	u := Unavailable{}
	if _, err := u.Get(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Get error = %v, want ErrUnavailable", err)
	}
	if err := u.Set(secret.Secret("x")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Set error = %v, want ErrUnavailable", err)
	}
	if err := u.Delete(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Delete error = %v, want ErrUnavailable", err)
	}
}

func TestFakeRoundTrips(t *testing.T) {
	f := &Fake{}
	if _, err := f.Get(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Fake Get = %v, want ErrNotFound", err)
	}
	if err := f.Set(secret.Secret("k")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := f.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expose() != "k" {
		t.Errorf("Get = %q, want k", got.Expose())
	}
	if err := f.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !f.Deleted {
		t.Error("Deleted flag not set")
	}
	if _, err := f.Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// A Secret must not render its contents even when a backend errors.
func TestErrorsNeverQuoteTheValue(t *testing.T) {
	r := &recorder{err: errors.New("exit status 1")}
	err := Security{Run: r.run}.Set(secret.Secret("master-key-marker"))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "master-key-marker") {
		t.Errorf("LEAK: error quoted the value: %v", err)
	}
}
