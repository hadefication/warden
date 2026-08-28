package classify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/secret"
)

func readSchema(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env.schema"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSetClassCreatesTheSchemaWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path, err := SetClass(dir, "FOO_KEY", Public)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, ".env.schema"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}

	sch, err := LoadSchema(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := sch.Lookup("FOO_KEY"); !ok || c != Public {
		t.Errorf("Lookup = (%v, %v), want (public, true)", c, ok)
	}
}

func TestSetClassSeedsAHeaderSoTheFileExplainsItself(t *testing.T) {
	dir := t.TempDir()
	if _, err := SetClass(dir, "FOO_KEY", Public); err != nil {
		t.Fatal(err)
	}
	body := readSchema(t, dir)
	if !strings.HasPrefix(body, "#") {
		t.Errorf("a created schema must open with an explanatory comment, got %q", body)
	}
	if !strings.HasSuffix(body, "FOO_KEY=public\n") {
		t.Errorf("got %q, want it to end with the new entry", body)
	}
}

func TestSetClassPreservesCommentsAndUnrelatedEntries(t *testing.T) {
	dir := writeSchema(t, "# hand written\nEXISTING=secret\n\n# trailing note\n")
	if _, err := SetClass(dir, "NEW_ONE", Public); err != nil {
		t.Fatal(err)
	}
	body := readSchema(t, dir)
	for _, want := range []string{"# hand written", "EXISTING=secret", "# trailing note", "NEW_ONE=public"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lost %q:\n%s", want, body)
		}
	}
}

func TestSetClassUpdatesAnExistingEntryInPlace(t *testing.T) {
	dir := writeSchema(t, "MODE=public\nOTHER=secret\n")
	if _, err := SetClass(dir, "MODE", Secret); err != nil {
		t.Fatal(err)
	}
	if got, want := readSchema(t, dir), "MODE=secret\nOTHER=secret\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSetClassRoundTripsThroughClassify(t *testing.T) {
	// The written entry must actually change the verdict, not merely land in the
	// file. DB_PASSWORD is secret by name pattern; the override flips it.
	dir := t.TempDir()
	if _, err := SetClass(dir, "DB_PASSWORD", Public); err != nil {
		t.Fatal(err)
	}
	sch, err := LoadSchema(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := Classify("DB_PASSWORD", secret.Secret("plain"), sch)
	if got.Class != Public || got.Rule != "schema" {
		t.Errorf("got %s (%s), want public (schema)", got.Class, got.Rule)
	}
}

func TestSetClassRefusesToCreateThroughASymlink(t *testing.T) {
	// os.Stat follows symlinks, so a *dangling* link at .env.schema reports
	// IsNotExist — and a naive create would write through it to the target.
	// Creating with O_EXCL refuses instead of handing anyone an arbitrary-file
	// write primitive, however narrow.
	dir := t.TempDir()
	target := filepath.Join(dir, "victim.txt")
	if err := os.Symlink(target, filepath.Join(dir, ".env.schema")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if _, err := SetClass(dir, "FOO_KEY", Public); err == nil {
		t.Error("creating the schema through a symlink must be refused")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("the symlink target was written (stat err = %v)", err)
	}
}

func TestShapeRuleReportsRecognisedCredentialFormats(t *testing.T) {
	for _, tc := range []struct{ value, rule string }{
		{"sk_live_abc", "shape:stripe-live"},
		{"ghp_abc", "shape:github-pat"},
		{"https://admin:pw@host", "shape:url-userinfo"},
	} {
		rule, ok := ShapeRule(secret.Secret(tc.value))
		if !ok || rule != tc.rule {
			t.Errorf("ShapeRule(%q) = (%q, %v), want (%q, true)", tc.value, rule, ok, tc.rule)
		}
	}
}

func TestShapeRuleIgnoresOrdinaryValues(t *testing.T) {
	for _, v := range []string{"", "Warden", "https://example.test", "12345"} {
		if rule, ok := ShapeRule(secret.Secret(v)); ok {
			t.Errorf("ShapeRule(%q) = (%q, true), want false", v, rule)
		}
	}
}
