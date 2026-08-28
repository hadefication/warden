package query

import (
	"testing"
	"time"

	"github.com/webteractive/warden/internal/keyring"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/secret"
	"github.com/webteractive/warden/internal/vault"
)

var vaultNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// seedVault writes a vault into a temp home through internal/vault directly,
// which is what the query package is a read-only view over.
func seedVault(t *testing.T, entries ...vault.Entry) (home string, kr *keyring.Fake) {
	t.Helper()
	home = t.TempDir()
	kr = &keyring.Fake{}

	v, err := vault.Open(vault.Options{
		Home: home, Keyring: kr, Prompt: prompt.Fake{}, Now: func() time.Time { return vaultNow },
	})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for _, e := range entries {
		if err := v.Put(e); err != nil {
			t.Fatalf("seed put %q: %v", e.Name, err)
		}
	}
	if err := v.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	VaultKeyring = kr
	VaultNow = func() time.Time { return vaultNow }
	t.Cleanup(func() { VaultKeyring, VaultNow = nil, nil })
	return home, kr
}

func TestVaultListReturnsMetadataAndNoValues(t *testing.T) {
	home, _ := seedVault(t,
		vault.Entry{Name: "stripe/live", Key: "STRIPE_SECRET", Value: secret.Secret("marker-a")},
		vault.Entry{Name: "tmp/token", Key: "TMP_TOKEN", Value: secret.Secret("marker-b"),
			Expires: vaultNow.Add(3 * time.Hour)},
	)

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	rows := q.List()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Name != "stripe/live" || rows[0].Key != "STRIPE_SECRET" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if !rows[0].Permanent {
		t.Error("stripe/live has no deadline and should be permanent")
	}
	if rows[1].Permanent || !rows[1].Expires.Equal(vaultNow.Add(3*time.Hour)) {
		t.Errorf("row 1 = %+v, want a deadline three hours out", rows[1])
	}
	// VaultRow deliberately has no value field. This is the compile-time half of
	// the guarantee; the canary suite is the runtime half.
}

func TestVaultHasIgnoresExpiredEntries(t *testing.T) {
	home, _ := seedVault(t,
		vault.Entry{Name: "live", Key: "A", Value: secret.Secret("v"), Expires: vaultNow.Add(time.Hour)},
		vault.Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: vaultNow.Add(time.Minute)},
	)

	later := vaultNow.Add(30 * time.Minute)
	VaultNow = func() time.Time { return later }

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if !q.Has("live") {
		t.Error("Has(live) = false, want true")
	}
	if q.Has("dead") {
		t.Error("Has(dead) = true — an expired entry must read as absent")
	}
	if q.Has("never-existed") {
		t.Error("Has of an unknown name should be false")
	}
}

func TestOpenVaultOnAMissingVaultIsEmptyRatherThanAnError(t *testing.T) {
	home := t.TempDir()
	VaultKeyring = &keyring.Fake{}
	t.Cleanup(func() { VaultKeyring = nil })

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault on a missing vault = %v, want nil", err)
	}
	if q.Exists() {
		t.Error("Exists should be false")
	}
	if len(q.List()) != 0 {
		t.Error("List should be empty")
	}
}
