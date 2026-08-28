package write

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/classify"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
)

// spy records what the confirmation prompt was asked, if it was asked at all.
type spy struct {
	asked   bool
	class   string
	key     string
	retyped bool
}

func (s *spy) prompter(err error) prompt.Prompter {
	return prompt.Fake{
		ConfirmErr: err,
		OnConfirm: func(class, key, _ string, retypeKey bool) {
			s.asked, s.class, s.key, s.retyped = true, class, key, retypeKey
		},
	}
}

func schemaBody(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env.schema"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func noSchema(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, ".env.schema")); !os.IsNotExist(err) {
		t.Fatalf("a refusal must not create .env.schema (stat err = %v)", err)
	}
}

func TestReclassifyToPublicRecordsTheOverride(t *testing.T) {
	dir := project(t, "FOO_KEY=plain\n")
	s := &spy{}
	if err := open(t, dir, s.prompter(nil)).Reclassify("FOO_KEY", classify.Public); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(schemaBody(t, dir), "FOO_KEY=public") {
		t.Errorf("schema = %q, want the override recorded", schemaBody(t, dir))
	}
}

func TestReclassifyToPublicDemandsTheKeyBeRetyped(t *testing.T) {
	dir := project(t, "FOO_KEY=plain\n")
	s := &spy{}
	if err := open(t, dir, s.prompter(nil)).Reclassify("FOO_KEY", classify.Public); err != nil {
		t.Fatal(err)
	}
	if !s.asked {
		t.Fatal("loosening a key's class must not happen without asking")
	}
	if !s.retyped {
		t.Error("--set public must require retyping the key, not a single button press")
	}
	if s.class != "public" || s.key != "FOO_KEY" {
		t.Errorf("prompt saw (%q, %q), want (public, FOO_KEY)", s.class, s.key)
	}
}

func TestReclassifyToSecretAsksButNeedsNoRetype(t *testing.T) {
	// Tightening cannot leak anything, so it gets a plain confirmation.
	dir := project(t, "MODE=normal\n")
	s := &spy{}
	if err := open(t, dir, s.prompter(nil)).Reclassify("MODE", classify.Secret); err != nil {
		t.Fatal(err)
	}
	if !s.asked {
		t.Fatal("even tightening should be authorised by a human")
	}
	if s.retyped {
		t.Error("--set secret must not demand retyping — it loosens nothing")
	}
	if !strings.Contains(schemaBody(t, dir), "MODE=secret") {
		t.Errorf("schema = %q", schemaBody(t, dir))
	}
}

func TestReclassifyRefusesGlobalScope(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte("GH_TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open(query.Scope{Global: true, Dir: home, Home: home}, prompt.Fake{})
	if err != nil {
		t.Fatal(err)
	}
	s := &spy{}
	w.p = s.prompter(nil)

	if err := w.Reclassify("GH_TOKEN", classify.Public); !errors.Is(err, ErrGlobalScope) {
		t.Fatalf("err = %v, want ErrGlobalScope", err)
	}
	if s.asked {
		t.Error("a scope refusal must land before the user is bothered")
	}
	noSchema(t, home)
}

func TestReclassifyToPublicRefusesCredentialShapedValues(t *testing.T) {
	// Shape detection outranks the schema, so this override would be inert.
	// Refusing beats writing an entry that silently does nothing.
	dir := project(t, "MODE=sk_live_abc123\n")
	s := &spy{}
	err := open(t, dir, s.prompter(nil)).Reclassify("MODE", classify.Public)
	if !errors.Is(err, ErrUnwaivableShape) {
		t.Fatalf("err = %v, want ErrUnwaivableShape", err)
	}
	if s.asked {
		t.Error("do not make the user retype a key only to refuse afterwards")
	}
	if strings.Contains(err.Error(), "sk_live_abc123") {
		t.Error("the refusal echoed the value it was protecting")
	}
	// "use set --secret" is advice for a value write. Repeating it here would send
	// the user off to a command that does not do what they asked for.
	if strings.Contains(err.Error(), "set --secret") {
		t.Errorf("the refusal gives advice for the wrong command: %v", err)
	}
	if !strings.Contains(err.Error(), "shape:stripe-live") {
		t.Errorf("the refusal should name the rule that fired: %v", err)
	}
	noSchema(t, dir)
}

func TestReclassifyToSecretIsFineForCredentialShapedValues(t *testing.T) {
	dir := project(t, "MODE=sk_live_abc123\n")
	if err := open(t, dir, (&spy{}).prompter(nil)).Reclassify("MODE", classify.Secret); err != nil {
		t.Fatalf("err = %v, want nil — tightening is always allowed", err)
	}
}

func TestReclassifyToPublicIsAllowedForKeysSecretOnlyByName(t *testing.T) {
	// Fixing a heuristic miss is the whole point of the feature: DB_PASSWORD
	// matches a name pattern, but its value is not credential-shaped.
	dir := project(t, "DB_PASSWORD=not-really-a-password\n")
	if err := open(t, dir, (&spy{}).prompter(nil)).Reclassify("DB_PASSWORD", classify.Public); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

func TestDeclinedConfirmationWritesNothing(t *testing.T) {
	dir := project(t, "FOO_KEY=plain\n")
	err := open(t, dir, (&spy{}).prompter(prompt.ErrCancelled)).Reclassify("FOO_KEY", classify.Public)
	if !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("err = %v, want ErrCancelled", err)
	}
	noSchema(t, dir)
}

func TestReclassifyTakesEffectImmediately(t *testing.T) {
	// The open W must not keep serving the pre-write schema. Before the
	// reclassify, SetPublic on this key is refused; after it, it succeeds.
	dir := project(t, "FOO_KEY=plain\n")
	w := open(t, dir, (&spy{}).prompter(nil))

	if err := w.SetPublic("FOO_KEY", "x"); !errors.Is(err, ErrSecretKey) {
		t.Fatalf("precondition: err = %v, want ErrSecretKey", err)
	}
	if err := w.Reclassify("FOO_KEY", classify.Public); err != nil {
		t.Fatal(err)
	}
	if err := w.SetPublic("FOO_KEY", "x"); err != nil {
		t.Errorf("err = %v — the new class should be live on this W", err)
	}
}
