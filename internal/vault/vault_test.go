package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/secret"
)

var testNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// opts builds Options against a temp home and a fake keyring. No test may touch
// the real keyring or the real $HOME.
func opts(t *testing.T) (Options, *keyring.Fake) {
	t.Helper()
	kr := &keyring.Fake{}
	return Options{
		Home:    t.TempDir(),
		Keyring: kr,
		Prompt:  prompt.Fake{Value: "test-passphrase"},
		Now:     func() time.Time { return testNow },
	}, kr
}

func TestOpenOnAMissingFileYieldsAnEmptyVault(t *testing.T) {
	o, _ := opts(t)
	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v — a missing vault is not an error on the read path", err)
	}
	if v.Exists() {
		t.Error("Exists should be false before anything is saved")
	}
	if len(v.List()) != 0 {
		t.Errorf("List = %v, want empty", v.List())
	}
	if _, err := os.Stat(v.Path()); !os.IsNotExist(err) {
		t.Error("Open must not create the file; only Save does")
	}
}

func TestPathIsUnderDotWarden(t *testing.T) {
	home := t.TempDir()
	if got, want := Path(home), filepath.Join(home, ".warden", "vault"); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestSaveThenOpenRoundTripsThroughTheKeyring(t *testing.T) {
	const marker = "vault-marker-3d71fe02"
	o, kr := opts(t)

	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(Entry{Name: "stripe/live", Key: "STRIPE_SECRET", Value: secret.Secret(marker)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !kr.Present {
		t.Fatal("Save should have stored a master key in the keyring")
	}

	raw, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatal("the vault file contains the plaintext value")
	}
	if !strings.HasPrefix(string(raw), "warden-vault v1 keyring -") {
		t.Errorf("header line is %q", strings.SplitN(string(raw), "\n", 2)[0])
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get("stripe/live")
	if !ok {
		t.Fatal("the entry did not survive the round trip")
	}
	if got.Value.Expose() != marker {
		t.Errorf("value = %q, want %q", got.Value.Expose(), marker)
	}
	if got.Created.IsZero() {
		t.Error("Put should stamp Created from the injected clock")
	}
}

func TestSaveWritesModeSixHundred(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	if err := v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(v.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestSaveReassertsModeAndReportsThatItFoundItLoosened(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(v.Path(), 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.Loosened() {
		t.Error("Loosened should report a vault found more permissive than 0600")
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, _ := os.Stat(reopened.Path())
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode after save = %o, want 600", perm)
	}
}

// The single most destructive thing this package could do.
func TestAVaultWhoseKeyIsGoneIsRefusedAndNeverRekeyed(t *testing.T) {
	o, kr := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	before, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatal(err)
	}

	// The keychain item is gone: a restored backup, or a wiped keychain.
	kr.Present, kr.Value = false, ""

	_, err = Open(o)
	if !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("Open = %v, want ErrNoMasterKey", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "keychain") || !strings.Contains(msg, "delete") {
		t.Errorf("message %q should name restoring the keychain item and deleting the vault", msg)
	}

	after, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the vault file was rewritten — a fresh key was generated and the data is gone")
	}
}

func TestArgon2idModeDerivesFromThePassphrase(t *testing.T) {
	const marker = "vault-marker-argon-7c31"
	o, kr := opts(t)

	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if kr.Present {
		t.Error("argon2id mode must not put anything in the keyring")
	}

	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v.Mode() != ModeArgon2id {
		t.Fatalf("mode = %q, want argon2id", v.Mode())
	}
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret(marker)})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get("A")
	if !ok || got.Value.Expose() != marker {
		t.Errorf("argon2id round trip failed: ok=%v value=%q", ok, got.Value.Expose())
	}
}

func TestTheWrongPassphraseFailsAuthentication(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	wrong := o
	wrong.Prompt = prompt.Fake{Value: "not-the-passphrase"}
	if _, err := Open(wrong); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("Open with the wrong passphrase = %v, want ErrUndecryptable", err)
	}
}

func TestACancelledPassphrasePromptWritesNothing(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cancelled := o
	cancelled.Prompt = prompt.Fake{Err: prompt.ErrCancelled}
	if _, err := Open(cancelled); !errors.Is(err, prompt.ErrCancelled) {
		t.Errorf("Open = %v, want ErrCancelled", err)
	}
}

func TestInitRefusesAnExistingVault(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeKeyring); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := Init(o, ModeKeyring); !errors.Is(err, ErrExists) {
		t.Errorf("second Init = %v, want ErrExists", err)
	}
}

func TestPutValidatesNameKeyAndTTL(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)

	if err := v.Put(Entry{Name: "bad name", Key: "A", Value: secret.Secret("v")}); !errors.Is(err, ErrBadName) {
		t.Errorf("Put with a bad name = %v, want ErrBadName", err)
	}
	if err := v.Put(Entry{Name: "ok", Key: "lower", Value: secret.Secret("v")}); !errors.Is(err, ErrBadKey) {
		t.Errorf("Put with a bad key = %v, want ErrBadKey", err)
	}
	tooLong := Entry{
		Name: "ok", Key: "A", Value: secret.Secret("v"),
		Expires: testNow.Add(MaxTTL + time.Hour),
	}
	if err := v.Put(tooLong); !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("Put beyond the cap = %v, want ErrTTLTooLong", err)
	}
}

func TestPutReplacesByName(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("first")})
	_ = v.Put(Entry{Name: "a", Key: "B", Value: secret.Secret("second")})

	if n := len(v.List()); n != 1 {
		t.Fatalf("got %d entries, want 1 — Put should replace by name", n)
	}
	got, _ := v.Get("a")
	if got.Value.Expose() != "second" || got.Key != "B" {
		t.Errorf("entry = %q/%q, want second/B", got.Value.Expose(), got.Key)
	}
}

// Two entries with the same target key is the whole reason names exist.
func TestTwoEntriesMayShareATargetKey(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	if err := v.Put(Entry{Name: "acme/db", Key: "DB_PASSWORD", Value: secret.Secret("one")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Put(Entry{Name: "beta/db", Key: "DB_PASSWORD", Value: secret.Secret("two")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n := len(v.List()); n != 2 {
		t.Fatalf("got %d entries, want 2", n)
	}
}

func TestListIsSortedByName(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	for _, n := range []string{"zeta", "alpha", "mid/one"} {
		_ = v.Put(Entry{Name: n, Key: "A", Value: secret.Secret("v")})
	}
	got := []string{v.List()[0].Name, v.List()[1].Name, v.List()[2].Name}
	want := []string{"alpha", "mid/one", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List order = %v, want %v", got, want)
		}
	}
}

func TestAnExpiredEntryIsInvisibleToListAndGet(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "live", Key: "A", Value: secret.Secret("v"), Expires: testNow.Add(time.Hour)})
	_ = v.Put(Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: testNow.Add(-time.Second)})

	if n := len(v.List()); n != 1 || v.List()[0].Name != "live" {
		t.Fatalf("List = %v, want only the live entry", v.List())
	}
	if _, ok := v.Get("dead"); ok {
		t.Error("Get returned an expired entry — expired must be indistinguishable from absent")
	}
}

func TestSavePurgesExpiredEntries(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "live", Key: "A", Value: secret.Secret("v")})
	_ = v.Put(Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: testNow.Add(time.Minute)})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	later := o
	later.Now = func() time.Time { return testNow.Add(time.Hour) }
	reopened, err := Open(later)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A third open with the clock rolled back proves the entry is gone from the
	// file rather than merely filtered by the clock.
	back, err := Open(o)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	if _, ok := back.Get("dead"); ok {
		t.Error("the expired entry survived the reseal — Save must purge it")
	}
	if _, ok := back.Get("live"); !ok {
		t.Error("Save purged a permanent entry")
	}
}

func TestRemoveAndRename(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})

	if err := v.Rename("a", "b/c"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, ok := v.Get("a"); ok {
		t.Error("the old name still resolves")
	}
	if _, ok := v.Get("b/c"); !ok {
		t.Error("the new name does not resolve")
	}
	if err := v.Rename("nope", "x"); !errors.Is(err, ErrNoVault) {
		t.Errorf("Rename of an absent entry = %v, want ErrNoVault", err)
	}
	if err := v.Rename("b/c", "bad name"); !errors.Is(err, ErrBadName) {
		t.Errorf("Rename to an illegal name = %v, want ErrBadName", err)
	}

	if !v.Remove("b/c") {
		t.Error("Remove should report that it removed something")
	}
	if v.Remove("b/c") {
		t.Error("Remove of an absent entry should report false")
	}
}

// Two writers, one file. The whole document reseals on every write, so an
// unguarded second writer silently drops the first writer's entry.
func TestSaveIsSerialisedByALockfile(t *testing.T) {
	o, _ := opts(t)
	first, _ := Open(o)
	_ = first.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := first.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	lock := first.Path() + ".lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lock) })
	_ = f.Close()

	second, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = second.Put(Entry{Name: "b", Key: "B", Value: secret.Secret("v")})
	if err := second.Save(); !errors.Is(err, ErrLocked) {
		t.Errorf("Save while locked = %v, want ErrLocked", err)
	}

	reopened, _ := Open(o)
	if _, ok := reopened.Get("a"); !ok {
		t.Error("the held lock did not protect the existing entry")
	}
}

func TestAStaleLockIsBrokenRatherThanBlockingForever(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	lock := v.Path() + ".lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	stale := time.Now().Add(-2 * lockStaleAfter)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}

	_ = v.Put(Entry{Name: "b", Key: "B", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Errorf("Save with a stale lock = %v, want it broken and the save to proceed", err)
	}
}

// A crash mid-write must leave the previous vault, never a truncated one.
func TestSaveLeavesNoTemporaryFileBehind(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(v.Path()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "vault" {
			t.Errorf("stray file left in ~/.warden: %s", e.Name())
		}
	}
}
