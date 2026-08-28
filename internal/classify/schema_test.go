package classify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/webteractive/warden/internal/secret"
)

func writeSchema(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env.schema"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadSchemaAbsentIsNotAnError(t *testing.T) {
	sch, err := LoadSchema(t.TempDir())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if sch != nil {
		t.Error("absent schema must return a nil *Schema")
	}
}

func TestSchemaOverridesBeatEveryHeuristic(t *testing.T) {
	dir := writeSchema(t, "# override file\nMY_PUBLIC_KEY=public\nAPP_NAME=secret\n")
	sch, err := LoadSchema(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Name pattern says *_KEY is secret; the schema says otherwise and wins.
	got := Classify("MY_PUBLIC_KEY", secret.Secret("abc"), sch)
	if got.Class != Public || got.Rule != "schema" {
		t.Errorf("MY_PUBLIC_KEY = %s (%s), want public (schema)", got.Class, got.Rule)
	}

	// Allowlist says APP_NAME is public; the schema says otherwise and wins.
	got = Classify("APP_NAME", secret.Secret("Warden"), sch)
	if got.Class != Secret || got.Rule != "schema" {
		t.Errorf("APP_NAME = %s (%s), want secret (schema)", got.Class, got.Rule)
	}
}

func TestSchemaDoesNotOverrideValueShape(t *testing.T) {
	// Declaring a key public must not expose a value that is demonstrably a
	// live credential. Shape detection is the one thing a schema cannot waive.
	dir := writeSchema(t, "TOKEN_MODE=public\n")
	sch, _ := LoadSchema(dir)
	got := Classify("TOKEN_MODE", secret.Secret("sk_live_abc123"), sch)
	if got.Class != Secret {
		t.Errorf("got %s (%s), want secret — shape must outrank a schema override", got.Class, got.Rule)
	}
}

func TestUnlistedKeysFallThroughToHeuristics(t *testing.T) {
	dir := writeSchema(t, "SOMETHING=public\n")
	sch, _ := LoadSchema(dir)
	if got := Classify("DB_PASSWORD", secret.Secret("x"), sch); got.Class != Secret {
		t.Errorf("DB_PASSWORD = %s, want secret", got.Class)
	}
	if got := Classify("APP_NAME", secret.Secret("x"), sch); got.Class != Public {
		t.Errorf("APP_NAME = %s, want public", got.Class)
	}
}

func TestInvalidClassIsAnError(t *testing.T) {
	dir := writeSchema(t, "THING=maybe\n")
	if _, err := LoadSchema(dir); err == nil {
		t.Error("an unrecognised class must be an error, not silently ignored")
	}
}
