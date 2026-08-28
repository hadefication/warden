package write

import (
	"errors"
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

func TestUnsetRemovesASetKeyAfterConfirmation(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\nGH_TOKEN=abc\n")
	var asked string
	w := open(t, dir, prompt.Fake{OnAction: func(action, key, _ string) { asked = action + ":" + key }})

	n, err := w.Unset("GH_TOKEN")
	if err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if n != 1 {
		t.Errorf("removed %d, want 1", n)
	}
	if asked != "remove:GH_TOKEN" {
		t.Errorf("the user was asked %q, want remove:GH_TOKEN", asked)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("got %q", got)
	}
}

// Removal is destructive, and a value the user cannot recover is worth a
// deliberate yes even though nothing is revealed.
func TestUnsetWritesNothingWhenTheUserDeclines(t *testing.T) {
	const body = "APP_NAME=Warden\nGH_TOKEN=abc\n"
	dir := project(t, body)
	w := open(t, dir, prompt.Fake{ConfirmErr: prompt.ErrCancelled})

	if _, err := w.Unset("GH_TOKEN"); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if got := read(t, dir); got != body {
		t.Errorf("a declined removal must leave the file byte-identical; got %q", got)
	}
}

func TestUnsetOfAnAbsentKeyReportsItWithoutAskingAnyone(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\n")
	asked := false
	w := open(t, dir, prompt.Fake{OnAction: func(string, string, string) { asked = true }})

	if _, err := w.Unset("ABSENT"); !errors.Is(err, ErrAbsent) {
		t.Errorf("err = %v, want ErrAbsent", err)
	}
	if asked {
		t.Error("there is nothing to authorise when the key does not exist")
	}
}

// An empty key holds nothing the user can lose, so the ceremony would be noise.
func TestUnsetOfAnEmptyKeyNeedsNoConfirmation(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\nEMPTY_TOKEN=\n")
	asked := false
	w := open(t, dir, prompt.Fake{OnAction: func(string, string, string) { asked = true }})

	if n, err := w.Unset("EMPTY_TOKEN"); err != nil || n != 1 {
		t.Fatalf("Unset = %d, %v; want 1, nil", n, err)
	}
	if asked {
		t.Error("an empty key holds nothing to lose")
	}
	if got := read(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("got %q", got)
	}
}

func TestUnsetRemovesEveryAssignmentOfADuplicatedKey(t *testing.T) {
	dir := project(t, "GH_TOKEN=old\nAPP_NAME=Warden\nGH_TOKEN=new\n")
	w := open(t, dir, prompt.Fake{})

	n, err := w.Unset("GH_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("removed %d, want 2 — leaving the earlier line would resurrect an old credential", n)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("got %q", got)
	}
}

func TestClearEmptiesTheValueButKeepsTheDeclaration(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\nGH_TOKEN=abc\n")
	var asked string
	w := open(t, dir, prompt.Fake{OnAction: func(action, key, _ string) { asked = action + ":" + key }})

	if err := w.Clear("GH_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if asked != "clear:GH_TOKEN" {
		t.Errorf("the user was asked %q, want clear:GH_TOKEN", asked)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\nGH_TOKEN=\n" {
		t.Errorf("got %q", got)
	}
}

func TestClearOfAnAlreadyEmptyKeyIsANoOp(t *testing.T) {
	dir := project(t, "EMPTY_TOKEN=\n")
	asked := false
	w := open(t, dir, prompt.Fake{OnAction: func(string, string, string) { asked = true }})

	if err := w.Clear("EMPTY_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Error("nothing is being destroyed")
	}
}

func TestClearOfAnAbsentKeyReportsItRatherThanDeclaringIt(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\n")
	if err := open(t, dir, prompt.Fake{}).Clear("ABSENT"); !errors.Is(err, ErrAbsent) {
		t.Errorf("err = %v, want ErrAbsent", err)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\n" {
		t.Errorf("clear must not create a key; got %q", got)
	}
}

// Secret keys are the reason these commands exist: hand-editing the file is the
// forbidden operation, so warden has to offer the sanctioned one.
func TestUnsetWorksOnSecretKeys(t *testing.T) {
	dir := project(t, "STRIPE_SECRET=sk_live_abc\n")
	if _, err := open(t, dir, prompt.Fake{}).Unset("STRIPE_SECRET"); err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if got := read(t, dir); got != "" {
		t.Errorf("got %q", got)
	}
}
