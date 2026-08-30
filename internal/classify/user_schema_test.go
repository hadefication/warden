package classify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/secret"
)

func readUserRegistry(t *testing.T, home string) map[string]map[string]string {
	t.Helper()
	b, err := os.ReadFile(UserSchemaPath(home))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]map[string]string
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("registry is not valid JSON: %v\n%s", err, b)
	}
	return got
}

func canonicalPath(t *testing.T, path string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestLoadUserSchemaAbsentIsNotAnError(t *testing.T) {
	sch, err := LoadUserSchema(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if sch != nil {
		t.Error("absent user schema must return a nil *Schema")
	}
}

func TestUserSchemaKeepsProjectsIsolatedInOneRegistry(t *testing.T) {
	home := t.TempDir()
	projectA := t.TempDir()
	projectB := t.TempDir()

	if _, err := SetUserClass(home, projectA, "SHARED_KEY", Public); err != nil {
		t.Fatal(err)
	}
	if _, err := SetUserClass(home, projectB, "SHARED_KEY", Secret); err != nil {
		t.Fatal(err)
	}

	a, err := LoadUserSchema(home, projectA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadUserSchema(home, projectB)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := a.Lookup("SHARED_KEY"); !ok || c != Public {
		t.Errorf("project A = (%s, %v), want (public, true)", c, ok)
	}
	if c, ok := b.Lookup("SHARED_KEY"); !ok || c != Secret {
		t.Errorf("project B = (%s, %v), want (secret, true)", c, ok)
	}
	if got := len(readUserRegistry(t, home)); got != 2 {
		t.Errorf("registry has %d projects, want 2", got)
	}
}

func TestUserSchemaUsesTheCanonicalProjectRoot(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	alias := filepath.Join(t.TempDir(), "project-link")
	if err := os.Symlink(project, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := SetUserClass(home, alias, "FOO_KEY", Public); err != nil {
		t.Fatal(err)
	}
	sch, err := LoadUserSchema(home, project)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := sch.Lookup("FOO_KEY"); !ok || c != Public {
		t.Errorf("canonical lookup = (%s, %v), want (public, true)", c, ok)
	}
	canonical := canonicalPath(t, project)
	if _, ok := readUserRegistry(t, home)[canonical]; !ok {
		t.Errorf("registry is not keyed by canonical project path %q", canonical)
	}
}

func TestUserSchemaWinsOverLegacyProjectSchemaAndBuiltins(t *testing.T) {
	home := t.TempDir()
	project := writeSchema(t, "FOO_KEY=secret\nAPP_NAME=public\n")
	if _, err := SetUserClass(home, project, "FOO_KEY", Public); err != nil {
		t.Fatal(err)
	}
	if _, err := SetUserClass(home, project, "APP_NAME", Secret); err != nil {
		t.Fatal(err)
	}
	user, _ := LoadUserSchema(home, project)
	legacy, _ := LoadSchema(project)

	if got := Classify("FOO_KEY", secret.Secret("plain"), user, legacy); got.Class != Public || got.Rule != "user-schema" {
		t.Errorf("FOO_KEY = %s (%s), want public (user-schema)", got.Class, got.Rule)
	}
	if got := Classify("APP_NAME", secret.Secret("Warden"), user, legacy); got.Class != Secret || got.Rule != "user-schema" {
		t.Errorf("APP_NAME = %s (%s), want secret (user-schema)", got.Class, got.Rule)
	}
}

func TestValueShapeStillWinsOverBothSchemaLayers(t *testing.T) {
	home := t.TempDir()
	project := writeSchema(t, "MODE=public\n")
	if _, err := SetUserClass(home, project, "MODE", Public); err != nil {
		t.Fatal(err)
	}
	user, _ := LoadUserSchema(home, project)
	legacy, _ := LoadSchema(project)

	got := Classify("MODE", secret.Secret("sk_live_abc123"), user, legacy)
	if got.Class != Secret || got.Rule != "shape:stripe-live" {
		t.Errorf("MODE = %s (%s), want secret (shape:stripe-live)", got.Class, got.Rule)
	}
}

func TestLoadUserSchemaRejectsMalformedJSONAndClasses(t *testing.T) {
	project := t.TempDir()
	for _, tc := range []struct {
		name string
		body string
	}{
		{"malformed JSON", `{`},
		{"invalid class", `{"/project":{"FOO":"maybe"}}`},
		{"trailing document", `{} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, ".warden"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(UserSchemaPath(home), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadUserSchema(home, project); err == nil {
				t.Error("invalid registry must be rejected")
			}
		})
	}
}

func TestSetUserClassPreservesUnrelatedEntriesAndUsesPrivateModes(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	other := t.TempDir()
	if _, err := SetUserClass(home, other, "EXISTING", Secret); err != nil {
		t.Fatal(err)
	}
	path, err := SetUserClass(home, project, "NEW_KEY", Public)
	if err != nil {
		t.Fatal(err)
	}

	registry := readUserRegistry(t, home)
	if registry[canonicalPath(t, other)]["EXISTING"] != "secret" || registry[canonicalPath(t, project)]["NEW_KEY"] != "public" {
		t.Errorf("unrelated entries were not preserved: %#v", registry)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Errorf("stat schema directory: %v", err)
	} else if fi.Mode().Perm() != 0o700 {
		t.Errorf("schema directory mode = %v; want 0700", fi.Mode().Perm())
	}
	if fi, err := os.Stat(path); err != nil {
		t.Errorf("stat schema: %v", err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("schema mode = %v; want 0600", fi.Mode().Perm())
	}
}

func TestUserSchemaRefusesSymlinks(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".warden"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "victim.json")
	original := `{"keep":{"THIS":"secret"}}`
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, UserSchemaPath(home)); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := LoadUserSchema(home, project); err == nil {
		t.Error("reading a symlinked registry must be refused")
	}
	if _, err := SetUserClass(home, project, "FOO", Public); err == nil {
		t.Error("writing a symlinked registry must be refused")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != original {
		t.Errorf("symlink target changed: %q", b)
	}
}

func TestFailedUserSchemaUpdateLeavesExistingFileUntouched(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".warden"), 0o700); err != nil {
		t.Fatal(err)
	}
	original := `{"/project":{"FOO":"maybe"}}`
	if err := os.WriteFile(UserSchemaPath(home), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := SetUserClass(home, project, "BAR", Public); err == nil {
		t.Fatal("updating an invalid registry must fail")
	}
	b, err := os.ReadFile(UserSchemaPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != original {
		t.Errorf("failed update changed the registry: %q", b)
	}
}
