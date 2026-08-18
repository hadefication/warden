// Package keyring stores warden's vault master key in the operating system's
// keyring.
//
// Warden holds exactly one item, so the interface takes no service or account
// arguments — the constants below are the whole address space.
//
// Both backends shell out, because .goreleaser.yaml sets CGO_ENABLED=0 and that
// is what lets the installer drop one static file onto a machine with no
// toolchain. The consequence is written down in the vault spec: a keychain ACL
// protects /usr/bin/security rather than warden, so any process that can run
// security can read this key. Encryption at rest defends a synced backup, a
// stolen laptop and a cat of the file — not a local process.
package keyring

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hadefication/warden/internal/secret"
)

// The item's address in the OS keyring.
const (
	service = "warden"
	account = "vault-master"
)

var (
	// ErrNotFound means the keyring holds no item for warden.
	ErrNotFound = errors.New("no vault master key in the keyring")
	// ErrUnavailable means this machine offers no keyring to use.
	ErrUnavailable = errors.New("no OS keyring available")
)

// Keyring holds the vault's master key.
type Keyring interface {
	// Get returns the stored key, or ErrNotFound.
	Get() (secret.Secret, error)
	// Set stores the key, replacing any existing one.
	Set(v secret.Secret) error
	// Delete removes the item. Removing an absent item is not an error.
	Delete() error
}

// Runner executes a backend command. It is the seam tests replace: the master
// key must reach the child on stdin and never through args, because argv is
// world-readable via ps.
type Runner func(name, stdin string, args ...string) ([]byte, error)

// execRun is the production Runner. stderr is discarded deliberately: security
// writes "password data for new item:" prompts there even when piped, and that
// is noise rather than diagnosis.
func execRun(name, stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.Output()
}

// Default picks the backend for this machine, or Unavailable when there is none.
func Default() Keyring {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return Security{Run: execRun}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil {
			return SecretTool{Run: execRun}
		}
	}
	return Unavailable{}
}

// Unavailable is the backend for a machine with no keyring. Every method
// refuses, which is what sends the vault down its passphrase path.
type Unavailable struct{}

func (Unavailable) Get() (secret.Secret, error) { return "", ErrUnavailable }
func (Unavailable) Set(secret.Secret) error     { return ErrUnavailable }
func (Unavailable) Delete() error               { return ErrUnavailable }

// Fake is a test double. No test may touch a real keyring.
type Fake struct {
	Value   secret.Secret
	Present bool
	GetErr  error
	SetErr  error
	Deleted bool
}

func (f *Fake) Get() (secret.Secret, error) {
	if f.GetErr != nil {
		return "", f.GetErr
	}
	if !f.Present {
		return "", ErrNotFound
	}
	return f.Value, nil
}

func (f *Fake) Set(v secret.Secret) error {
	if f.SetErr != nil {
		return f.SetErr
	}
	f.Value, f.Present = v, true
	return nil
}

func (f *Fake) Delete() error {
	f.Value, f.Present, f.Deleted = "", false, true
	return nil
}

// wrapErr reports a backend failure without ever quoting the value, and without
// piping the child's stderr through either. The caller is frequently an agent; a
// failed write is not a reason to disclose a key, and subprocess output is not
// something warden's leak tests cover.
//
// What it does instead is name the causes, because "exit status 154" is not
// something a user can act on. Every one of these is a real way to reach here:
// an ssh session with no access to the login keychain, a keychain that is locked,
// a CI runner with no keyring at all, or a $HOME that does not hold the keychain
// security expects to find.
func wrapErr(op string, err error) error {
	return fmt.Errorf(
		"keyring %s failed (%w) — the OS keyring refused. Common causes: the login keychain is "+
			"locked, this is an ssh or CI session without access to it, or $HOME does not point at "+
			"the keychain. A passphrase vault needs no keyring: warden vault init --passphrase",
		op, err)
}
