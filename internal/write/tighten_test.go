package write

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
)

// schema returns the central registry's contents, or "" when none was written.
func schema(t *testing.T, home string) string {
	t.Helper()
	b, err := os.ReadFile(classify.UserSchemaPath(home))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetSecretTightensAKeyThatWouldOtherwiseBePublic(t *testing.T) {
	// The gap this closes: VITE_* is on the public allowlist, so before this
	// change you could store a value through the secret channel and still have
	// `warden get` hand it straight back.
	dir := project(t, "")
	if err := open(t, dir, prompt.Fake{Value: "hunter2"}).SetSecret("VITE_ANALYTICS_ID"); err != nil {
		t.Fatal(err)
	}

	got := schema(t, dir)
	if !strings.Contains(got, "VITE_ANALYTICS_ID") || !strings.Contains(got, "secret") {
		t.Fatalf("want VITE_ANALYTICS_ID recorded as secret, got %q", got)
	}
}

func TestSetSecretTighteningSurvivesReopening(t *testing.T) {
	// The override is only worth writing if a later read actually sees it.
	dir := project(t, "")
	if err := open(t, dir, prompt.Fake{Value: "hunter2"}).SetSecret("VITE_ANALYTICS_ID"); err != nil {
		t.Fatal(err)
	}

	w := open(t, dir, prompt.Fake{})
	if got := w.classOf("VITE_ANALYTICS_ID").Class; got != classify.Secret {
		t.Errorf("class = %v, want Secret", got)
	}
}

func TestSetSecretWritesNoOverrideForAnAlreadySecretKey(t *testing.T) {
	// Most keys are secret by the fail-closed default. Recording that would fill
	// the registry with entries that change nothing.
	dir := project(t, "")
	if err := open(t, dir, prompt.Fake{Value: "hunter2"}).SetSecret("DB_PASSWORD"); err != nil {
		t.Fatal(err)
	}
	if got := schema(t, dir); strings.Contains(got, "DB_PASSWORD") {
		t.Errorf("a redundant override was written: %q", got)
	}
}

func TestSetSecretDoesNotTightenInGlobalScope(t *testing.T) {
	// ~/.secrets is secret by definition, so there is no override to record and
	// no project to record it against.
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(query.Scope{Global: true, Home: home}, prompt.Fake{Value: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.SetSecret("VITE_ANALYTICS_ID"); err != nil {
		t.Fatal(err)
	}
	if got := schema(t, home); got != "" {
		t.Errorf("global scope wrote a registry entry: %q", got)
	}
}

func TestSetSecretTighteningNeverAsksForConfirmation(t *testing.T) {
	// Tightening removes access; it has never needed authorising. Asking here
	// would teach the ceremony to mean "confirm", which is what must not happen.
	dir := project(t, "")
	asked := false
	p := prompt.Fake{
		Value:      "hunter2",
		ConfirmErr: prompt.ErrCancelled, // would block if it were consulted
		OnConfirm:  func(string, string, string, bool) { asked = true },
	}
	if err := open(t, dir, p).SetSecret("VITE_ANALYTICS_ID"); err != nil {
		t.Fatal(err)
	}
	if asked {
		t.Error("tightening asked for confirmation")
	}
}
