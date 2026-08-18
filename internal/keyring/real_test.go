package keyring

import (
	"fmt"
	"os"
	"testing"

	"github.com/hadefication/warden/internal/secret"
)

// Every other test here drives a Runner seam or the Fake, which means nothing
// exercises the actual `security` / `secret-tool` invocations. This one does,
// and is skipped unless you ask for it:
//
//	WARDEN_REAL_KEYRING_CHECK=1 go test ./internal/keyring/ -run TestRealKeyring -v
//
// It writes and then deletes warden's real keychain item, so it refuses to run
// at all if one already exists — deleting the master key of a vault that holds
// entries is the one unrecoverable mistake in this codebase.
func TestRealKeyringRoundTripAgainstTheOSKeyring(t *testing.T) {
	if os.Getenv("WARDEN_REAL_KEYRING_CHECK") != "1" {
		t.Skip("set WARDEN_REAL_KEYRING_CHECK=1 to exercise the real OS keyring")
	}

	kr := Default()
	if _, ok := kr.(Unavailable); ok {
		t.Skip("no OS keyring on this machine")
	}
	t.Logf("backend: %T", kr)

	if _, err := kr.Get(); err == nil {
		t.Fatal("a warden master key already exists — refusing to touch it. " +
			"If a vault depends on it, deleting it would destroy every entry")
	}

	const probe = "cHJvYmUtdmFsdWUtZm9yLXdhcmRlbi1jaGVjay0xMjM0NTY3OA=="
	if err := kr.Set(secret.Secret(probe)); err != nil {
		t.Fatalf("Set: %v", err)
	}
	t.Cleanup(func() { _ = kr.Delete() })

	got, err := kr.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expose() != probe {
		// The failure this catches: security asks for the value twice, and
		// piping it once leaves the item created with an empty password.
		t.Fatalf("round trip returned %d bytes, want the %d-byte probe — "+
			"the backend is not storing what it was given", len(got.Expose()), len(probe))
	}
	if rendered := fmt.Sprintf("%v", got); rendered != secret.Redacted {
		t.Errorf("the key rendered as %q rather than %q", rendered, secret.Redacted)
	}

	if err := kr.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := kr.Get(); err == nil {
		t.Error("the item survived Delete")
	}
}
