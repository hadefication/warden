package write

import (
	"errors"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

// These pin the boundaries of `warden set --public` and `--exposed`, the two
// flags that let a caller reach the store on easier terms than the secret
// channel. Each test below corresponds to a way the pair could be turned into
// an escalation, and each one was reachable before these guards existed.

// A refused command must not leave state behind. This is the sharpest of the
// lot: Loosen used to persist the override and only then let SetPublic reject
// the value, so the operator saw an error, believed nothing had happened, and
// had in fact just made the key permanently readable.
func TestLoosenLeavesNoOverrideWhenTheValueIsRefused(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})

	err := w.Loosen("CF_GROUP_ID", "postgres://admin:hunter2@db.internal:5432/app")
	if !errors.Is(err, ErrUnwaivableShape) {
		t.Fatalf("err = %v, want ErrUnwaivableShape", err)
	}
	if got := schema(t, dir); strings.Contains(got, "CF_GROUP_ID") {
		t.Errorf("a refused command recorded an override anyway: %q", got)
	}
}

// The flag is scoped to keys that are secret only because warden fails closed.
// A key a rule actually recognised is a different claim, and overriding it from
// the same command that supplies the value skips the ceremony built for it.
func TestLoosenRefusesAKeyThatMatchedARule(t *testing.T) {
	for _, key := range []string{"DB_PASSWORD", "STRIPE_SECRET_KEY"} {
		t.Run(key, func(t *testing.T) {
			dir := project(t, "")
			err := open(t, dir, prompt.Fake{}).Loosen(key, "harmless")
			if !errors.Is(err, ErrRuleMatched) {
				t.Fatalf("err = %v, want ErrRuleMatched", err)
			}
			if got := schema(t, dir); strings.Contains(got, key) {
				t.Errorf("override was recorded anyway: %q", got)
			}
		})
	}
}

// The case the flag does serve: a name no rule recognised, secret only by the
// closing default.
func TestLoosenAllowsAFailClosedKey(t *testing.T) {
	dir := project(t, "")
	if err := open(t, dir, prompt.Fake{}).Loosen("CF_GROUP_ID", "abc123"); err != nil {
		t.Fatalf("a fail-closed key is exactly what --public is for: %v", err)
	}
	if got := schema(t, dir); !strings.Contains(got, "CF_GROUP_ID") {
		t.Errorf("override was not recorded: %q", got)
	}
}

// SetExposed reaches the store without the prompt the secret channel imposes
// and without SetPublic's classification check. Overwriting a live value is
// therefore the one destructive write with nothing in front of it, unless it
// asks — Unset and Clear both already do.
func TestSetExposedConfirmsBeforeOverwritingALiveValue(t *testing.T) {
	dir := project(t, "DB_PASSWORD=the-real-one\n")
	var action string
	p := prompt.Fake{
		ConfirmErr: prompt.ErrCancelled,
		OnAction:   func(a, _, _ string) { action = a },
	}

	err := open(t, dir, p).SetExposed("DB_PASSWORD", "clobbered")
	if !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if action != "expose" {
		t.Errorf("action = %q, want %q — a generic verb renders the wrong dialog", action, "expose")
	}
	if got := read(t, dir); !strings.Contains(got, "the-real-one") {
		t.Errorf("a declined confirmation still overwrote the value: %q", got)
	}
}

// Provisioning a key that holds nothing destroys nothing, so it must not ask.
// A ceremony that fires when nothing is at stake trains the answer.
func TestSetExposedDoesNotAskForAnAbsentKey(t *testing.T) {
	dir := project(t, "")
	p := prompt.Fake{ConfirmErr: prompt.ErrCancelled} // fails if consulted at all

	if err := open(t, dir, p).SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatalf("nothing to destroy, so nothing to confirm: %v", err)
	}
}

// A key name is concatenated into the line, so a newline in one writes a second
// assignment the caller chose outright. Get resolves a duplicated key to its
// last assignment, which means the injected line wins over the real one above.
func TestWritePathsRejectAKeyThatWouldInjectALine(t *testing.T) {
	const inject = "Z\nDB_PASSWORD"

	t.Run("exposed", func(t *testing.T) {
		dir := project(t, "DB_PASSWORD=the-real-one\n")
		if err := open(t, dir, prompt.Fake{}).SetExposed(inject, "injected"); err == nil {
			t.Fatal("a key carrying a newline was accepted")
		}
		if got := read(t, dir); strings.Contains(got, "injected") {
			t.Errorf("the injected assignment reached the file: %q", got)
		}
	})

	t.Run("secret", func(t *testing.T) {
		dir := project(t, "DB_PASSWORD=the-real-one\n")
		p := prompt.Fake{Value: "injected"}
		if err := open(t, dir, p).SetSecret(inject); err == nil {
			t.Fatal("a key carrying a newline was accepted")
		}
		if got := read(t, dir); strings.Contains(got, "injected") {
			t.Errorf("the injected assignment reached the file: %q", got)
		}
	})

	t.Run("public", func(t *testing.T) {
		dir := project(t, "DB_PASSWORD=the-real-one\n")
		if err := open(t, dir, prompt.Fake{}).SetPublic(inject, "injected"); err == nil {
			t.Fatal("a key carrying a newline was accepted")
		}
		if got := read(t, dir); strings.Contains(got, "injected") {
			t.Errorf("the injected assignment reached the file: %q", got)
		}
	})
}
