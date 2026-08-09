package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func project(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// run executes the CLI and returns stdout, stderr and the resolved exit code.
func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errw bytes.Buffer
	err := Run(args, &out, &errw)
	return out.String(), errw.String(), ExitCode(err)
}

func TestHasPrintsNothingAndSignalsThroughExitCode(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nEMPTY=\n"})

	out, errw, code := run(t, "has", "APP_NAME", "--project", dir)
	if code != 0 {
		t.Errorf("set key: code = %d, want 0", code)
	}
	if out != "" || errw != "" {
		t.Errorf("has must print nothing; got out=%q err=%q", out, errw)
	}

	if _, _, code := run(t, "has", "EMPTY", "--project", dir); code != 1 {
		t.Errorf("empty key: code = %d, want 1", code)
	}
	if _, _, code := run(t, "has", "ABSENT", "--project", dir); code != 1 {
		t.Errorf("absent key: code = %d, want 1", code)
	}
}

func TestHasWorksForSecretKeys(t *testing.T) {
	dir := project(t, map[string]string{".env": "STRIPE_SECRET=sk_live_abc\n"})
	out, errw, code := run(t, "has", "STRIPE_SECRET", "--project", dir)
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if out+errw != "" {
		t.Errorf("has leaked output: %q %q", out, errw)
	}
}

func TestHasWithoutAnEnvFileIsAnError(t *testing.T) {
	if _, _, code := run(t, "has", "A", "--project", t.TempDir()); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
}

func TestListShowsClassAndStateButNoValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nDB_PASSWORD=hunter2\nEMPTY_TOKEN=\n"})
	out, _, code := run(t, "list", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "Warden") {
		t.Fatalf("list leaked a value:\n%s", out)
	}
	for _, want := range []string{"APP_NAME", "public", "DB_PASSWORD", "secret", "EMPTY_TOKEN", "unset"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestListJSON(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nDB_PASSWORD=hunter2\n"})
	out, _, code := run(t, "list", "--project", dir, "--json")
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("json list leaked a value: %s", out)
	}
	var rows []struct {
		Key   string `json:"key"`
		Class string `json:"class"`
		Set   bool   `json:"set"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(rows) != 2 || rows[1].Class != "secret" || !rows[1].Set {
		t.Errorf("unexpected rows: %+v", rows)
	}
}

func TestClassifyExplainsTheRule(t *testing.T) {
	dir := project(t, map[string]string{".env": "STRIPE_KEY=abc\n"})
	out, _, code := run(t, "classify", "STRIPE_KEY", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "secret") || !strings.Contains(out, "name:*_KEY") {
		t.Errorf("want class and rule in output, got:\n%s", out)
	}
}

func TestGlobalScopeTargetsSecretsFile(t *testing.T) {
	home := project(t, map[string]string{".secrets": "export GH_TOKEN=ghp_abc\n"})
	t.Setenv("HOME", home)
	if _, _, code := run(t, "has", "GH_TOKEN", "--global"); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	out, _, _ := run(t, "list", "--global")
	if strings.Contains(out, "ghp_abc") {
		t.Fatalf("global list leaked a value:\n%s", out)
	}
}

func TestUnknownCommandExitsThree(t *testing.T) {
	if _, _, code := run(t, "frobnicate"); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
}
