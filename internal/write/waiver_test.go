package write

import (
	"errors"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/prompt"
)

// The retype ceremony guards one moment: an existing secret becoming readable.
// A key holding no value has nothing to disclose, so the retype there costs the
// user a dialog and buys nothing — and a ceremony that fires when nothing is at
// stake is how people learn to click through the one that matters.
//
// The plain confirmation stays. Reclassify is a standalone act the user invoked
// on its own, and warden's existing position is that a human authorises every
// classification change. Only the retype is waived here.

func TestReclassifyToPublicWaivesTheRetypeForAnAbsentKey(t *testing.T) {
	dir := project(t, "")
	var called, retyped bool
	p := prompt.Fake{OnConfirm: func(_, _, _ string, retype bool) {
		called, retyped = true, retype
	}}

	if err := open(t, dir, p).Reclassify("CF_GROUP_ID", classify.Public); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("a classification change is still authorised by a human")
	}
	if retyped {
		t.Error("an absent key has nothing to reveal — the retype is pointless here")
	}
}

func TestReclassifyToPublicWaivesTheRetypeForADeclaredButEmptyKey(t *testing.T) {
	dir := project(t, "CF_GROUP_ID=\n")
	retyped := false
	p := prompt.Fake{OnConfirm: func(_, _, _ string, retype bool) { retyped = retype }}

	if err := open(t, dir, p).Reclassify("CF_GROUP_ID", classify.Public); err != nil {
		t.Fatal(err)
	}
	if retyped {
		t.Error("a declared-but-empty key holds nothing to reveal")
	}
}

func TestReclassifyToPublicStillDemandsTheRetypeForAKeyHoldingAValue(t *testing.T) {
	dir := project(t, "CF_GROUP_ID=abc123\n")
	var called, retyped bool
	p := prompt.Fake{OnConfirm: func(_, _, _ string, retype bool) {
		called, retyped = true, retype
	}}

	if err := open(t, dir, p).Reclassify("CF_GROUP_ID", classify.Public); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("a key holding a value must still be authorised")
	}
	if !retyped {
		t.Error("loosening a live value must demand the retype, not a plain confirm")
	}
}

// Loosen is the provisioning path behind `warden set --public`. It exists
// because passing the flag IS the authorisation: the user typed the class they
// want, on a key that holds nothing, in the same breath as the value.

func TestLoosenRecordsPublicWithoutAsking(t *testing.T) {
	dir := project(t, "")
	p := prompt.Fake{ConfirmErr: prompt.ErrCancelled} // fails if consulted at all

	if err := open(t, dir, p).Loosen("CF_GROUP_ID", "abc123"); err != nil {
		t.Fatalf("provisioning a new key should not need a dialog: %v", err)
	}
	if got := schema(t, dir); !strings.Contains(got, "CF_GROUP_ID") {
		t.Errorf("override was not recorded: %q", got)
	}
}

func TestLoosenAcceptsADeclaredButEmptyKey(t *testing.T) {
	dir := project(t, "CF_GROUP_ID=\n")
	if err := open(t, dir, prompt.Fake{ConfirmErr: prompt.ErrCancelled}).Loosen("CF_GROUP_ID", "abc123"); err != nil {
		t.Fatalf("a declared-but-empty key holds nothing to reveal: %v", err)
	}
}

func TestLoosenRefusesAKeyThatAlreadyHoldsAValue(t *testing.T) {
	// This is the case the retype ceremony exists for. The quiet path must not
	// become a second, weaker way to reach it.
	dir := project(t, "CF_API_TOKEN=live-value\n")

	err := open(t, dir, prompt.Fake{}).Loosen("CF_API_TOKEN", "abc123")
	if !errors.Is(err, ErrHasValue) {
		t.Fatalf("err = %v, want ErrHasValue", err)
	}
	if got := schema(t, dir); strings.Contains(got, "CF_API_TOKEN") {
		t.Errorf("override was recorded anyway: %q", got)
	}
}

func TestLoosenRefusesInGlobalScope(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	w.global = true

	if err := w.Loosen("CF_GROUP_ID", "abc123"); !errors.Is(err, ErrGlobalScope) {
		t.Fatalf("err = %v, want ErrGlobalScope", err)
	}
}
