package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

// End-to-end cover for the ways `set` could be turned into an escalation. The
// write package pins the same rules at its own layer; these check the command
// actually routes into them and reports the refusal usefully.

// The sharpest of the group: the command printed an error, exited non-zero, and
// had already made the key permanently readable. An operator told "no" has
// every reason to believe nothing happened.
func TestSetPublicRefusalLeavesClassificationUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	_, errw, code := run(t, "set", "--public", "CF_GROUP_ID",
		"postgres://admin:hunter2@db.internal:5432/app", "--project", dir)
	if code == 0 {
		t.Fatal("a credential-shaped value must be refused")
	}
	if !strings.Contains(errw, "nothing was changed") {
		t.Errorf("the refusal should say the command had no effect: %q", errw)
	}

	out, _, code := run(t, "classify", "CF_GROUP_ID", "--project", dir)
	if code != 0 {
		t.Fatalf("classify failed: %d", code)
	}
	if strings.Contains(out, "public") {
		t.Errorf("a refused command still made the key public: %q", out)
	}
}

// --public is for a key that is secret only because warden fails closed. A key
// a rule recognised has to go through the full ceremony instead.
func TestSetPublicRefusesARuleMatchedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	_, errw, code := run(t, "set", "--public", "DB_PASSWORD", "harmless", "--project", dir)
	if code == 0 {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(errw, "classify DB_PASSWORD --set public") {
		t.Errorf("the refusal should name the deliberate path: %q", errw)
	}

	out, _, _ := run(t, "classify", "DB_PASSWORD", "--project", dir)
	if strings.Contains(out, "public") {
		t.Errorf("the key was loosened anyway: %q", out)
	}
}

// The case --public does serve, kept alongside the refusals so a future tighten
// cannot quietly close the flag altogether.
func TestSetPublicAllowsAFailClosedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	if _, errw, code := run(t, "set", "--public", "CF_GROUP_ID", "abc123", "--project", dir); code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	out, _, _ := run(t, "get", "CF_GROUP_ID", "--project", dir)
	if !strings.Contains(out, "abc123") {
		t.Errorf("the key should now be readable: %q", out)
	}
}

// The --from-file guard refuses a path naming one of warden's own stores.
// Comparing cleaned absolute paths catches "../.secrets" and misses a symlink
// pointing at the same file, which makes the guard a guard against typing.
func TestFromFileGuardFollowsSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	secrets := filepath.Join(home, ".secrets")
	if err := os.WriteFile(secrets, []byte("GH_TOKEN=ghp_realvalue\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	link := filepath.Join(t.TempDir(), "innocent.txt")
	if err := os.Symlink(secrets, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, errw, code := run(t, "set", "--secret", "STOLEN", "--from-file", link, "--project", dir)
	if code == 0 {
		t.Fatal("a symlink to ~/.secrets reached the same file the direct path refuses")
	}
	if !strings.Contains(errw, "warden manages") {
		t.Errorf("unexpected refusal: %q", errw)
	}
	if got := readEnv(t, dir); strings.Contains(got, "ghp_realvalue") {
		t.Errorf("the secrets file's contents were copied in: %q", got)
	}
}

// --exposed reaches the store without the prompt the secret channel imposes and
// without SetPublic's classification check, so overwriting a live value is the
// one destructive write with nothing in front of it unless it asks.
func TestSetExposedConfirmsBeforeClobberingALiveValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "LIVE_TOKEN=the-real-one\n"})
	withPrompter(t, prompt.Fake{ConfirmErr: prompt.ErrCancelled})

	if _, _, code := run(t, "set", "--exposed", "LIVE_TOKEN", "clobbered", "--project", dir); code == 0 {
		t.Fatal("a declined confirmation must refuse the write")
	}
	if got := readEnv(t, dir); !strings.Contains(got, "the-real-one") {
		t.Errorf("the live value was overwritten anyway: %q", got)
	}
}

// Provisioning a key that holds nothing destroys nothing, so it must not ask.
func TestSetExposedDoesNotConfirmForANewKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	// Fails the test if a confirmation is requested at all.
	withPrompter(t, prompt.Fake{ConfirmErr: prompt.ErrCancelled})

	if _, errw, code := run(t, "set", "--exposed", "NEW_TOKEN", "abc123", "--project", dir); code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
}

// A key name carrying a newline writes a second assignment the caller chose,
// and Get resolves a duplicated key to its last one — so the injected line wins
// over the real one above it.
func TestSetRejectsAKeyThatWouldInjectALine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "DB_PASSWORD=the-real-one\n"})

	_, _, code := run(t, "set", "--exposed", "Z\nDB_PASSWORD", "injected", "--project", dir)
	if code == 0 {
		t.Fatal("a key carrying a newline was accepted")
	}
	if got := readEnv(t, dir); strings.Contains(got, "injected") {
		t.Errorf("the injected assignment reached the file: %q", got)
	}
}
