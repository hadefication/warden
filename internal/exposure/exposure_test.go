package exposure

import (
	"os"
	"strings"
	"testing"
)

func TestRecordThenList(t *testing.T) {
	home := t.TempDir()
	if err := Record(home, "/proj", "CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	got, err := List(home, "/proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "CF_API_TOKEN" {
		t.Errorf("got %v, want [CF_API_TOKEN]", got)
	}
}

func TestListIsEmptyWhenNothingWasEverRecorded(t *testing.T) {
	// A missing file is the normal state, not an error.
	got, err := List(t.TempDir(), "/proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestRecordIsIdempotent(t *testing.T) {
	home := t.TempDir()
	for range 3 {
		if err := Record(home, "/proj", "CF_API_TOKEN"); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := List(home, "/proj")
	if len(got) != 1 {
		t.Errorf("got %v, want one entry", got)
	}
}

func TestScopesAreIndependent(t *testing.T) {
	home := t.TempDir()
	if err := Record(home, "/a", "K1"); err != nil {
		t.Fatal(err)
	}
	if err := Record(home, "/b", "K2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := List(home, "/a"); len(got) != 1 || got[0] != "K1" {
		t.Errorf("scope /a = %v", got)
	}
	if got, _ := List(home, "/b"); len(got) != 1 || got[0] != "K2" {
		t.Errorf("scope /b = %v", got)
	}
}

func TestClearRemovesTheMark(t *testing.T) {
	// The mark means "this value reached a command line". Once the key is
	// rewritten through a channel that does not expose it, the old value is no
	// longer what is stored — so the warning has to stop, or doctor nags forever
	// and people learn to ignore it.
	home := t.TempDir()
	if err := Record(home, "/proj", "CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if err := Clear(home, "/proj", "CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if got, _ := List(home, "/proj"); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestClearIsSafeWhenNothingWasRecorded(t *testing.T) {
	if err := Clear(t.TempDir(), "/proj", "NEVER_SET"); err != nil {
		t.Errorf("clearing an unmarked key should be a no-op, got %v", err)
	}
}

func TestTheRecordNeverHoldsAValue(t *testing.T) {
	// This file records that an exposure happened. Storing the exposed value
	// would turn a warning into a second copy of the secret.
	home := t.TempDir()
	if err := Record(home, "/proj", "CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(Path(home))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "CF_API_TOKEN") {
		t.Fatalf("expected the key name in %s", Path(home))
	}
	// Only names may appear: the project scope and the key.
	for _, forbidden := range []string{"value", "secret=", "="} {
		if strings.Contains(string(b), forbidden) {
			t.Errorf("record looks like it carries a value: %q", b)
		}
	}
}

func TestTheRecordIsPrivate(t *testing.T) {
	home := t.TempDir()
	if err := Record(home, "/proj", "K"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(Path(home))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("permissions %04o — the list of burned keys is not public", st.Mode().Perm())
	}
}
