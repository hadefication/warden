package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

func envBody(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnsetRemovesTheKey(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nGH_TOKEN=abc\n"})

	out, _, code := run(t, "unset", "GH_TOKEN", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "GH_TOKEN") || !strings.Contains(out, ".env") {
		t.Errorf("output should name the key and the file, got %q", out)
	}
	if envBody(t, dir) != "APP_NAME=Warden\n" {
		t.Errorf("got %q", envBody(t, dir))
	}
}

func TestUnsetReportsHowManyAssignmentsItRemoved(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "GH_TOKEN=old\nAPP_NAME=Warden\nGH_TOKEN=new\n"})

	out, _, code := run(t, "unset", "GH_TOKEN", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out, "2") {
		t.Errorf("a duplicated key must say how many lines went, got %q", out)
	}
}

func TestUnsetOfAnAbsentKeyExitsOne(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	if _, _, code := run(t, "unset", "ABSENT", "--project", dir); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestUnsetDeclinedExitsThreeAndChangesNothing(t *testing.T) {
	withPrompter(t, prompt.Fake{ConfirmErr: prompt.ErrCancelled})
	const body = "APP_NAME=Warden\nGH_TOKEN=abc\n"
	dir := project(t, map[string]string{".env": body})

	if _, _, code := run(t, "unset", "GH_TOKEN", "--project", dir); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if envBody(t, dir) != body {
		t.Errorf("a declined removal must leave the file byte-identical; got %q", envBody(t, dir))
	}
}

func TestClearKeepsTheKeyDeclared(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "GH_TOKEN=abc\n"})

	if _, _, code := run(t, "clear", "GH_TOKEN", "--project", dir); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if envBody(t, dir) != "GH_TOKEN=\n" {
		t.Errorf("got %q", envBody(t, dir))
	}
	out, _, _ := run(t, "list", "--project", dir)
	if !strings.Contains(out, "GH_TOKEN") || !strings.Contains(out, "unset") {
		t.Errorf("a cleared key should still be listed as declared-but-unset, got %q", out)
	}
}

func TestUnsetWorksOnSecretKeys(t *testing.T) {
	withPrompter(t, prompt.Fake{})
	dir := project(t, map[string]string{".env": "STRIPE_SECRET=sk_live_abc\nAPP_NAME=Warden\n"})
	if _, _, code := run(t, "unset", "STRIPE_SECRET", "--project", dir); code != 0 {
		t.Errorf("code = %d, want 0 — refusing here would leave the file editable only by hand", code)
	}
}
