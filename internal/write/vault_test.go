package write

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
)

const vaultMarker = "vault-marker-8be40c17"

var wNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func vaultHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	query.VaultKeyring = &keyring.Fake{}
	query.VaultNow = func() time.Time { return wNow }
	t.Cleanup(func() { query.VaultKeyring, query.VaultNow = nil, nil })
	return home
}

// project(t, body) lives in write_test.go: it makes a .env to push into.

func TestVaultSetStoresWhatTheUserTyped(t *testing.T) {
	home := vaultHome(t)
	w, err := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := w.Set("stripe/live", "STRIPE_SECRET", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	q, err := query.OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault (read): %v", err)
	}
	if !q.Has("stripe/live") {
		t.Fatal("the entry was not persisted")
	}
	if rows := q.List(); rows[0].Key != "STRIPE_SECRET" || !rows[0].Permanent {
		t.Errorf("row = %+v, want STRIPE_SECRET and permanent", rows[0])
	}
}

func TestVaultSetWithATTLStampsADeadline(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("tmp", "TMP_TOKEN", 8*time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	row := q.List()[0]
	if row.Permanent {
		t.Fatal("an entry given a ttl is not permanent")
	}
	if !row.Expires.Equal(wNow.Add(8 * time.Hour)) {
		t.Errorf("expires = %v, want %v", row.Expires, wNow.Add(8*time.Hour))
	}
}

// Nothing may be written when the prompt is declined.
func TestVaultSetWritesNothingWhenTheUserCancels(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Err: prompt.ErrCancelled})
	if err := w.Set("a", "A", 0); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("Set = %v, want ErrCancelled", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".warden", "vault")); !os.IsNotExist(err) {
		t.Error("a cancelled Set created a vault file")
	}
}

// Replacing a live value destroys something that may not be recoverable, so it
// takes the plain ceremony — never the retype, which means disclosure.
func TestVaultSetOverAnExistingEntryAsksForConfirmation(t *testing.T) {
	home := vaultHome(t)
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action+":"+key) },
	}

	w, _ := OpenVault(home, p)
	if err := w.Set("a", "A", 0); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("a new entry should not need confirming, got %v", actions)
	}

	w2, _ := OpenVault(home, p)
	if err := w2.Set("a", "A", 0); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if len(actions) != 1 || !strings.HasPrefix(actions[0], "replace:") {
		t.Errorf("actions = %v, want one replace confirmation", actions)
	}
}

func TestVaultRemoveConfirmsAndDeletes(t *testing.T) {
	home := vaultHome(t)
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action) },
	}
	w, _ := OpenVault(home, p)
	if err := w.Set("a", "A", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := w.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(actions) != 1 || actions[0] != "remove" {
		t.Errorf("actions = %v, want one remove confirmation", actions)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if q.Has("a") {
		t.Error("the entry survived Remove")
	}
}

func TestVaultRemoveOfAnAbsentEntryIsRefusedWithoutAsking(t *testing.T) {
	home := vaultHome(t)
	asked := false
	p := prompt.Fake{OnAction: func(string, string, string) { asked = true }}
	w, _ := OpenVault(home, p)

	if err := w.Remove("nope"); err == nil {
		t.Fatal("want an error")
	}
	if asked {
		t.Error("the user was asked to authorise removing something that is not there")
	}
}

func TestVaultEditChangesNameKeyAndTTL(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("old", "OLD_KEY", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	ttl := 2 * time.Hour
	if err := w.Edit("old", EditOpts{NewName: "new/name", NewKey: "NEW_KEY", TTL: &ttl}); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if q.Has("old") {
		t.Error("the old name still resolves")
	}
	row := q.List()[0]
	if row.Name != "new/name" || row.Key != "NEW_KEY" {
		t.Errorf("row = %+v", row)
	}
	if !row.Expires.Equal(wNow.Add(2 * time.Hour)) {
		t.Errorf("expires = %v, want a two-hour window", row.Expires)
	}
}

func TestVaultEditCanClearATTL(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("a", "A", time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var none time.Duration
	if err := w.Edit("a", EditOpts{TTL: &none}); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if !q.List()[0].Permanent {
		t.Error("clearing the ttl should make the entry permanent")
	}
}

// The value must cross into the .env intact. This is the end-to-end half of the
// redaction trap: if a Secret were marshalled anywhere on this path, the project
// would receive the literal string "<redacted>".
func TestVaultPushWritesTheRealValueIntoTheDestination(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "APP_NAME=demo\n")

	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("stripe/live", "STRIPE_SECRET", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	res, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", false, true)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if res.Key != "STRIPE_SECRET" {
		t.Errorf("res.Key = %q", res.Key)
	}

	body, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "STRIPE_SECRET="+vaultMarker) {
		t.Fatalf("the destination did not receive the value:\n%s", body)
	}
	if strings.Contains(string(body), "<redacted>") {
		t.Fatal("the destination received the redaction marker instead of the value")
	}
}

func TestVaultPushRenamesInFlightWithAs(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("stripe/live", "STRIPE_SECRET", 0)

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "STRIPE_KEY", false, true); err != nil {
		t.Fatalf("Push: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "STRIPE_KEY="+vaultMarker) {
		t.Errorf("--as did not rename the key:\n%s", body)
	}
}

func TestVaultPushRefusesAnAlreadySetDestinationKeyUnlessForced(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "STRIPE_SECRET=already-here\n")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("stripe/live", "STRIPE_SECRET", 0)

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", false, true); !errors.Is(err, ErrDestinationSet) {
		t.Fatalf("Push = %v, want ErrDestinationSet", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "already-here") {
		t.Fatal("the refused push overwrote the destination anyway")
	}

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", true, true); err != nil {
		t.Fatalf("forced Push: %v", err)
	}
	body, _ = os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "STRIPE_SECRET="+vaultMarker) {
		t.Errorf("--force did not overwrite:\n%s", body)
	}
}

// Push moves a credential into a file that may well be committed, so it asks.
func TestVaultPushConfirmsUnlessYes(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action+":"+key) },
	}
	w, _ := OpenVault(home, p)
	_ = w.Set("a", "A_TOKEN", 0)

	if _, err := w.Push("a", query.Scope{Dir: dir}, "", false, false); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(actions) != 1 || actions[0] != "push:A_TOKEN" {
		t.Errorf("actions = %v, want one push confirmation naming the key", actions)
	}
}

func TestVaultPushWritesNothingWhenTheConfirmationIsDeclined(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("a", "A_TOKEN", 0)

	declining, _ := OpenVault(home, prompt.Fake{
		Value:      vaultMarker,
		ConfirmErr: prompt.ErrCancelled,
	})
	if _, err := declining.Push("a", query.Scope{Dir: dir}, "", false, false); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("Push = %v, want ErrCancelled", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if strings.Contains(string(body), vaultMarker) {
		t.Fatal("a declined push wrote the value anyway")
	}
}

func TestVaultPushOfAnAbsentOrExpiredEntryFails(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("gone", "GONE", time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	query.VaultNow = func() time.Time { return wNow.Add(2 * time.Hour) }
	later, err := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if _, err := later.Push("gone", query.Scope{Dir: dir}, "", false, true); err == nil {
		t.Error("pushing an expired entry should fail as absent")
	}
	if _, err := later.Push("never", query.Scope{Dir: dir}, "", false, true); err == nil {
		t.Error("pushing an unknown entry should fail")
	}
}

func TestInitVaultPassphraseModeIsRecorded(t *testing.T) {
	home := vaultHome(t)
	if err := InitVault(home, prompt.Fake{Value: "a-passphrase"}, true); err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	q, err := query.OpenVault(home, prompt.Fake{Value: "a-passphrase"})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if q.Mode() != "argon2id" {
		t.Errorf("mode = %q, want argon2id", q.Mode())
	}
}
