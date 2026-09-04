package write

import (
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

// An exposure warning has to be clearable by every action that disposes of the
// burned value, not just by rewriting the key.
//
// Removing the credential outright is the most complete remediation available,
// and it used to be the one that left the warning stuck: doctor went on
// reporting a key that no longer existed in the file, with no way to silence
// it, and --strict failed on a problem that had already been fixed. A warning
// nobody can clear is one people learn to scroll past, which costs the warnings
// that still mean something.

func TestUnsetClearsTheExposureRecord(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}
	if got := marked(t, dir, w.exposureScope()); len(got) != 1 {
		t.Fatalf("precondition failed, marked = %v", got)
	}

	if _, err := w.Unset("CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if got := marked(t, dir, w.exposureScope()); len(got) != 0 {
		t.Errorf("marked = %v, want none — the key is gone from the file", got)
	}
}

func TestClearClearsTheExposureRecord(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}

	if err := w.Clear("CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if got := marked(t, dir, w.exposureScope()); len(got) != 0 {
		t.Errorf("marked = %v, want none — the burned value is gone", got)
	}
}

// A declined confirmation must not clear the record either, since the burned
// value is still sitting in the file.
func TestDeclinedUnsetKeepsTheExposureRecord(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}

	declining := open(t, dir, prompt.Fake{ConfirmErr: prompt.ErrCancelled})
	if _, err := declining.Unset("CF_API_TOKEN"); err == nil {
		t.Fatal("expected the declined confirmation to refuse")
	}
	if got := marked(t, dir, w.exposureScope()); len(got) != 1 {
		t.Errorf("marked = %v, want the record kept — the value is still there", got)
	}
}
