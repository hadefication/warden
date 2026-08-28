package vault

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/webteractive/warden/internal/keyring"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/secret"
)

// The end-to-end proof: a value sealed with a key minted into the real OS
// keyring, and read back out of a real file on disk.
//
// Every other test here substitutes keyring.Fake, so the one thing never
// exercised is the join between them — mint, store, seal, reopen, unseal. Run:
//
//	WARDEN_REAL_KEYRING_CHECK=1 go test ./internal/vault/ -run TestRealKeyring -v
//
// The vault file goes to a temp dir while the keychain stays real, because the
// two are independent: Options.Home picks the file, keyring.Default() always
// talks to the login keychain. Overriding $HOME to relocate the file would break
// the keychain lookup instead — security resolves the login keychain through
// $HOME, and reports the failure as a cancelled authorisation.
func TestRealKeyringSealsAndReopensAVault(t *testing.T) {
	if os.Getenv("WARDEN_REAL_KEYRING_CHECK") != "1" {
		t.Skip("set WARDEN_REAL_KEYRING_CHECK=1 to exercise the real OS keyring")
	}

	kr := keyring.Default()
	if _, ok := kr.(keyring.Unavailable); ok {
		t.Skip("no OS keyring on this machine")
	}
	if _, err := kr.Get(); err == nil {
		t.Fatal("a warden master key already exists — refusing to touch it. " +
			"If a vault depends on it, replacing it would destroy every entry")
	}
	t.Cleanup(func() { _ = kr.Delete() })

	const marker = "real-keyring-marker-4b19ce7f"
	o := Options{
		Home:    t.TempDir(),
		Keyring: kr, // the real one
		Prompt:  prompt.Fake{},
		Now:     func() time.Time { return testNow },
	}

	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(Entry{Name: "real/check", Key: "REAL_CHECK", Value: secret.Secret(marker)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v — the real keyring refused to hold the master key", err)
	}

	raw, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatal("the value is readable in the file on disk")
	}
	if !strings.HasPrefix(string(raw), "warden-vault v1 keyring -") {
		t.Errorf("unexpected header: %q", strings.SplitN(string(raw), "\n", 2)[0])
	}

	// A fresh V, so the key comes back out of the keychain rather than memory.
	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v — the master key did not survive the round trip", err)
	}
	got, ok := reopened.Get("real/check")
	if !ok {
		t.Fatal("the entry did not survive")
	}
	if got.Value.Expose() != marker {
		t.Fatalf("value came back as %q, want %q", got.Value.Expose(), marker)
	}
	t.Logf("sealed and reopened %d bytes via %T", len(raw), kr)

	// Negative control. A passing round trip proves nothing on its own if the
	// key could have come from anywhere else — so take the keychain item away
	// and require the same reopen to fail, then put it back and require it to
	// work again. That is what makes the keychain demonstrably load-bearing.
	stored, err := kr.Get()
	if err != nil {
		t.Fatalf("reading the key back: %v", err)
	}
	if err := kr.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Open(o); !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("reopen without the keychain item = %v, want ErrNoMasterKey — "+
			"the vault opened without the key, so the key is not what unseals it", err)
	}

	if err := kr.Set(stored); err != nil {
		t.Fatalf("restoring the key: %v", err)
	}
	restored, err := Open(o)
	if err != nil {
		t.Fatalf("reopen after restoring the key: %v", err)
	}
	if got, ok := restored.Get("real/check"); !ok || got.Value.Expose() != marker {
		t.Fatal("the vault did not come back after the key was restored")
	}
	t.Log("negative control passed: removing the keychain item makes the vault unreadable")
}
