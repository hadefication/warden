package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
)

func readSchemaFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env.schema"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestClassifySetPublicRecordsTheOverrideAndSaysWhatChanged(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})

	out, errw, code := run(t, "classify", "FOO_KEY", "--set", "public", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, err = %q", code, errw)
	}
	if !strings.Contains(readSchemaFile(t, dir), "FOO_KEY=public") {
		t.Errorf("schema = %q", readSchemaFile(t, dir))
	}
	for _, want := range []string{"ok:", "FOO_KEY", "public"} {
		if !strings.Contains(out, want) {
			t.Errorf("confirmation missing %q: %q", want, out)
		}
	}
}

func TestClassifySetPublicWarnsThatTheValueIsNowReadable(t *testing.T) {
	// The whole consequence of the command is that `warden get` starts working on
	// this key. Saying so is the difference between a confirmation and a surprise.
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})

	out, _, _ := run(t, "classify", "FOO_KEY", "--set", "public", "--project", dir)
	if !strings.Contains(out, "get FOO_KEY") {
		t.Errorf("the confirmation should name what is now possible: %q", out)
	}
}

func TestClassifySetSecretRecordsTheOverride(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	_, errw, code := run(t, "classify", "APP_NAME", "--set", "secret", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, err = %q", code, errw)
	}
	if !strings.Contains(readSchemaFile(t, dir), "APP_NAME=secret") {
		t.Errorf("schema = %q", readSchemaFile(t, dir))
	}
}

func TestClassifyWithoutSetStillOnlyExplains(t *testing.T) {
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})
	out, _, code := run(t, "classify", "FOO_KEY", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "secret") {
		t.Errorf("the read path should still report the class: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.schema")); !os.IsNotExist(err) {
		t.Error("a plain classify must never write a schema")
	}
}

func TestClassifySetRejectsAnUnknownClass(t *testing.T) {
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})
	_, errw, code := run(t, "classify", "FOO_KEY", "--set", "publik", "--project", dir)
	if code == 0 {
		t.Fatal("an unrecognised class must be rejected")
	}
	if !strings.Contains(errw, "public") || !strings.Contains(errw, "secret") {
		t.Errorf("the rejection should list the valid classes: %q", errw)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.schema")); !os.IsNotExist(err) {
		t.Error("a rejected class must not write a schema")
	}
}

func TestClassifySetRejectsAnEmptyClass(t *testing.T) {
	// --set="" is an explicit request with a bad argument, not an absent flag.
	// Falling through to the read path would silently do something else.
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})
	_, errw, code := run(t, "classify", "FOO_KEY", "--set", "", "--project", dir)
	if code == 0 {
		t.Fatalf("an empty class must be rejected, got code 0 and err %q", errw)
	}
	if !strings.Contains(errw, "public") || !strings.Contains(errw, "secret") {
		t.Errorf("the rejection should list the valid classes: %q", errw)
	}
}

func TestClassifySetIsRefusedInGlobalScope(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte("GH_TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	withPrompter(t, prompt.Fake{})

	_, errw, code := run(t, "classify", "GH_TOKEN", "--set", "public", "--global")
	if code != CodeRefused {
		t.Errorf("code = %d, want %d", code, CodeRefused)
	}
	if !strings.Contains(errw, "global") {
		t.Errorf("the refusal should explain the scope rule: %q", errw)
	}
	if _, err := os.Stat(filepath.Join(home, ".env.schema")); !os.IsNotExist(err) {
		t.Error("nothing should have been written")
	}
}

func TestClassifySetPublicIsRefusedForCredentialShapedValues(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "MODE=sk_live_abc123\n"})

	out, errw, code := run(t, "classify", "MODE", "--set", "public", "--project", dir)
	if code != CodeRefused {
		t.Errorf("code = %d, want %d", code, CodeRefused)
	}
	if strings.Contains(out+errw, "sk_live_abc123") {
		t.Fatalf("the refusal echoed the credential: %q %q", out, errw)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.schema")); !os.IsNotExist(err) {
		t.Error("nothing should have been written")
	}
}

func TestDeclinedReclassificationExitsThreeAndWritesNothing(t *testing.T) {
	withPrompter(t, prompt.Fake{ConfirmErr: prompt.ErrCancelled})
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})

	_, _, code := run(t, "classify", "FOO_KEY", "--set", "public", "--project", dir)
	if code != CodeError {
		t.Errorf("code = %d, want %d", code, CodeError)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env.schema")); !os.IsNotExist(err) {
		t.Error("a declined confirmation must not write")
	}
}

func TestClassifySetHonoursTheJSONFlag(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "FOO_KEY=plain\n"})

	out, errw, code := run(t, "classify", "FOO_KEY", "--set", "public", "--json", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, err = %q", code, errw)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON (%v): %q", err, out)
	}
	if got["key"] != "FOO_KEY" || got["class"] != "public" {
		t.Errorf("got %v, want key=FOO_KEY class=public", got)
	}
	if got["path"] == "" {
		t.Error("the payload should name the file that changed")
	}
}

func TestReclassifyThenGetActuallyReadsTheValue(t *testing.T) {
	// End to end: the override has to change what a later, separate command does.
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "FOO_KEY=plain-not-a-secret\n"})

	if _, errw, code := run(t, "classify", "FOO_KEY", "--set", "public", "--project", dir); code != 0 {
		t.Fatalf("reclassify failed: code = %d, err = %q", code, errw)
	}
	out, errw, code := run(t, "get", "FOO_KEY", "--project", dir)
	if code != 0 {
		t.Fatalf("get after reclassify: code = %d, err = %q", code, errw)
	}
	if strings.TrimSpace(out) != "plain-not-a-secret" {
		t.Errorf("get returned %q", out)
	}
}
