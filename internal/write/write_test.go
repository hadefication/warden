package write

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
)

func project(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func open(t *testing.T, dir string, p prompt.Prompter) *W {
	t.Helper()
	w, err := Open(query.Scope{Dir: dir, Home: dir}, p)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func read(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetPublicWrites(t *testing.T) {
	dir := project(t, "APP_NAME=Old\n")
	if err := open(t, dir, prompt.Fake{}).SetPublic("APP_NAME", "New"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir); got != "APP_NAME=New\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetPublicRefusesSecretKeys(t *testing.T) {
	dir := project(t, "DB_PASSWORD=old\n")
	err := open(t, dir, prompt.Fake{}).SetPublic("DB_PASSWORD", "hunter2")
	if !errors.Is(err, ErrSecretKey) {
		t.Fatalf("err = %v, want ErrSecretKey", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the refusal echoed the attempted value")
	}
	if got := read(t, dir); got != "DB_PASSWORD=old\n" {
		t.Errorf("a refusal must not write: got %q", got)
	}
}

func TestSetPublicRefusesWhenTheNewValueLooksLikeACredential(t *testing.T) {
	// The key name is innocent, so classification of the *existing* value says
	// public — but the incoming value is a live Stripe key. Refuse it.
	dir := project(t, "MODE=normal\n")
	err := open(t, dir, prompt.Fake{}).SetPublic("MODE", "sk_live_abc123")
	if !errors.Is(err, ErrSecretKey) {
		t.Fatalf("err = %v, want ErrSecretKey", err)
	}
	if got := read(t, dir); got != "MODE=normal\n" {
		t.Errorf("nothing should have been written: got %q", got)
	}
}

func TestSetSecretUsesThePrompt(t *testing.T) {
	dir := project(t, "DB_PASSWORD=old\n")
	if err := open(t, dir, prompt.Fake{Value: "hunter2"}).SetSecret("DB_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir); got != "DB_PASSWORD=hunter2\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetSecretCreatesANewKey(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\n")
	if err := open(t, dir, prompt.Fake{Value: "sk_live_x"}).SetSecret("STRIPE_SECRET"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\nSTRIPE_SECRET=sk_live_x\n" {
		t.Errorf("got %q", got)
	}
}

func TestCancelledPromptIsACompleteNoOp(t *testing.T) {
	dir := project(t, "DB_PASSWORD=old\n")
	err := open(t, dir, prompt.Fake{Err: prompt.ErrCancelled}).SetSecret("DB_PASSWORD")
	if !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	if got := read(t, dir); got != "DB_PASSWORD=old\n" {
		t.Errorf("a cancelled prompt must not write: got %q", got)
	}
}

func TestSetSecretOnAPublicKeyIsAllowed(t *testing.T) {
	// Promoting a public key to a prompted write is always safe.
	dir := project(t, "APP_NAME=Warden\n")
	if err := open(t, dir, prompt.Fake{Value: "Renamed"}).SetSecret("APP_NAME"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir); got != "APP_NAME=Renamed\n" {
		t.Errorf("got %q", got)
	}
}
