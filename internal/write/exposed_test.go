package write

import (
	"testing"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/exposure"
	"github.com/webteractive/warden/internal/prompt"
)

func marked(t *testing.T, home, scope string) []string {
	t.Helper()
	got, err := exposure.List(home, scope)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSetExposedWritesTheValue(t *testing.T) {
	dir := project(t, "APP_NAME=Warden\n")
	if err := open(t, dir, prompt.Fake{}).SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}
	if got := read(t, dir); got != "APP_NAME=Warden\nCF_API_TOKEN=abc123\n" {
		t.Errorf("got %q", got)
	}
}

func TestSetExposedRecordsTheExposure(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}
	got := marked(t, dir, w.ProjectPath())
	if len(got) != 1 || got[0] != "CF_API_TOKEN" {
		t.Errorf("got %v, want [CF_API_TOKEN]", got)
	}
}

func TestSetExposedDoesNotMakeTheKeyReadable(t *testing.T) {
	// --exposed changes how the value got in. It says nothing about who may read
	// it, and warden get must still refuse.
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}
	if got := open(t, dir, prompt.Fake{}).classOf("CF_API_TOKEN").Class; got != classify.Secret {
		t.Errorf("class = %v, want Secret", got)
	}
}

func TestSetExposedAcceptsACredentialShapedValue(t *testing.T) {
	// SetPublic refuses these, and rightly. This path is *for* them: the flag
	// means "this credential is already burned", so refusing the shape would
	// refuse the only case the flag exists to serve.
	dir := project(t, "")
	if err := open(t, dir, prompt.Fake{}).SetExposed("STRIPE_KEY", "sk_live_abc123"); err != nil {
		t.Fatalf("want the write to succeed, got %v", err)
	}
}

func TestSetSecretClearsAPriorExposureMark(t *testing.T) {
	// Rotating through a safe channel is the fix. The warning has to stop when
	// the fix lands, or it stops meaning anything.
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("CF_API_TOKEN", "abc123"); err != nil {
		t.Fatal(err)
	}

	if err := open(t, dir, prompt.Fake{Value: "fresh"}).SetSecret("CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}
	if got := marked(t, dir, w.ProjectPath()); len(got) != 0 {
		t.Errorf("mark survived a safe rewrite: %v", got)
	}
}

func TestSetPublicClearsAPriorExposureMark(t *testing.T) {
	dir := project(t, "")
	w := open(t, dir, prompt.Fake{})
	if err := w.SetExposed("APP_NAME", "abc123"); err != nil {
		t.Fatal(err)
	}
	if err := open(t, dir, prompt.Fake{}).SetPublic("APP_NAME", "Warden"); err != nil {
		t.Fatal(err)
	}
	if got := marked(t, dir, w.ProjectPath()); len(got) != 0 {
		t.Errorf("mark survived a public rewrite: %v", got)
	}
}
