package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
)

func readEnv(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// withPrompter swaps the package prompter for the duration of a test.
func withPrompter(t *testing.T, p prompt.Prompter) {
	t.Helper()
	prev := SetPrompter
	SetPrompter = p
	t.Cleanup(func() { SetPrompter = prev })
}

func TestSetPublicKeyWrites(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Old\n"})
	out, _, code := run(t, "set", "APP_NAME", "New", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if got := readEnv(t, dir); got != "APP_NAME=New\n" {
		t.Errorf("got %q", got)
	}
	if !strings.Contains(out, "APP_NAME") {
		t.Errorf("expected a confirmation naming the key: %q", out)
	}
}

func TestSetRefusesSecretKeysWithGuidance(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})
	out, errw, code := run(t, "set", "DB_PASSWORD", "hunter2", "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if strings.Contains(out+errw, "hunter2") {
		t.Fatalf("the refusal echoed the attempted value: %q %q", out, errw)
	}
	if !strings.Contains(errw, "--secret") {
		t.Errorf("the refusal should point at set --secret: %q", errw)
	}
	if got := readEnv(t, dir); got != "DB_PASSWORD=old\n" {
		t.Errorf("a refusal must not write: %q", got)
	}
}

func TestSetSecretTakesNoValueArgument(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})
	out, errw, code := run(t, "set", "--secret", "DB_PASSWORD", "hunter2", "--project", dir)
	if code == 0 {
		t.Fatal("passing a value to set --secret must be rejected")
	}
	if strings.Contains(out+errw, "hunter2") {
		t.Fatalf("the rejection echoed the value: %q %q", out, errw)
	}
	if got := readEnv(t, dir); got != "DB_PASSWORD=old\n" {
		t.Errorf("nothing should have been written: %q", got)
	}
}

func TestSetSecretPromptsAndConfirmsWithoutTheValue(t *testing.T) {
	withPrompter(t, prompt.Fake{Value: "hunter2"})
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})

	out, errw, code := run(t, "set", "--secret", "DB_PASSWORD", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, err = %q", code, errw)
	}
	if got := readEnv(t, dir); got != "DB_PASSWORD=hunter2\n" {
		t.Errorf("got %q", got)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("the confirmation leaked the value: %q", out)
	}
	// No length or hash either — those leak too. Check the part before the file
	// path, since the path itself legitimately contains digits.
	prefix, _, _ := strings.Cut(out, " in ")
	if strings.ContainsAny(prefix, "0123456789") {
		t.Errorf("the confirmation appears to include a length or hash: %q", prefix)
	}
	for _, want := range []string{"ok:", "DB_PASSWORD", "secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("confirmation missing %q: %q", want, out)
		}
	}
}

func TestCancelledPromptWritesNothingAndExitsThree(t *testing.T) {
	withPrompter(t, prompt.Fake{Err: prompt.ErrCancelled})
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})

	_, _, code := run(t, "set", "--secret", "DB_PASSWORD", "--project", dir)
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if got := readEnv(t, dir); got != "DB_PASSWORD=old\n" {
		t.Errorf("a cancelled prompt must not write: %q", got)
	}
}

func TestSetRefusesAValueThatLooksLikeACredential(t *testing.T) {
	dir := project(t, map[string]string{".env": "MODE=normal\n"})
	out, errw, code := run(t, "set", "MODE", "sk_live_abc123", "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if strings.Contains(out+errw, "sk_live_abc123") {
		t.Fatalf("the refusal echoed the credential: %q %q", out, errw)
	}
	if got := readEnv(t, dir); got != "MODE=normal\n" {
		t.Errorf("nothing should have been written: %q", got)
	}
}
