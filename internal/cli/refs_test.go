package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree writes a project with source files alongside its .env.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRefsReportsBothDirections(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "APP_NAME=Warden\nOLD_KEY=x\n",
		"app/Mailer.php": "env('APP_NAME');\nenv('MAILGUN_SECRET');\n",
	})
	out, _, code := run(t, "refs", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d, want 0 — refs reports, --strict gates", code)
	}
	if !strings.Contains(out, "MAILGUN_SECRET") {
		t.Errorf("undeclared key missing from output:\n%s", out)
	}
	if !strings.Contains(out, "OLD_KEY") {
		t.Errorf("unreferenced key missing from output:\n%s", out)
	}
	if !strings.Contains(out, "app/Mailer.php") {
		t.Errorf("output should say where the reference is:\n%s", out)
	}
}

func TestRefsCanReportOneDirectionOnly(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "APP_NAME=Warden\nOLD_KEY=x\n",
		"app/Mailer.php": "env('MAILGUN_SECRET');\n",
	})
	out, _, _ := run(t, "refs", "--undeclared", "--project", dir)
	if !strings.Contains(out, "MAILGUN_SECRET") || strings.Contains(out, "OLD_KEY") {
		t.Errorf("--undeclared should show only the undeclared half:\n%s", out)
	}
}

func TestRefsStrictFailsOnAnUndeclaredKey(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "APP_NAME=Warden\n",
		"app/Mailer.php": "env('MAILGUN_SECRET');\n",
	})
	if _, _, code := run(t, "refs", "--strict", "--project", dir); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

// Unused is advisory: a key built at runtime looks exactly like a dead one.
func TestRefsStrictIgnoresUnreferencedKeys(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "APP_NAME=Warden\nOLD_KEY=x\n",
		"app/Mailer.php": "env('APP_NAME');\n",
	})
	if _, _, code := run(t, "refs", "--strict", "--project", dir); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestRefsIsRefusedInGlobalScope(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte("export A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if _, _, code := run(t, "refs", "--global"); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
}

func TestDoctorSaysWhenItDidNotCheckReferences(t *testing.T) {
	dir := tree(t, map[string]string{".env": "APP_NAME=Warden\n", ".env.example": "APP_NAME=\n"})
	out, _, _ := run(t, "doctor", "--project", dir)
	if !strings.Contains(out, "--refs") {
		t.Errorf("a silent omission reads as a clean bill of health:\n%s", out)
	}
}

func TestDoctorWithRefsFindsUndeclaredKeys(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "APP_NAME=Warden\n",
		".env.example":   "APP_NAME=\n",
		"app/Mailer.php": "env('MAILGUN_SECRET');\n",
	})
	out, _, code := run(t, "doctor", "--refs", "--strict", "--project", dir)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	if !strings.Contains(out, "MAILGUN_SECRET") {
		t.Errorf("output:\n%s", out)
	}
}

// Telling someone to revoke a credential that is not there sends them to a
// provider dashboard for nothing.
func TestRefsOnlySuggestsRevokingKeysThatHoldAValue(t *testing.T) {
	dir := tree(t, map[string]string{
		".env":           "LIVE_TOKEN=abc\nEMPTY_TOKEN=\n",
		"app/Mailer.php": "env('APP_NAME');\n",
	})
	out, _, _ := run(t, "refs", "--unused", "--project", dir)

	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "EMPTY_TOKEN") && strings.Contains(line, "revoke") {
			t.Errorf("an unset key has nothing to revoke:\n%s", line)
		}
	}
	if !strings.Contains(out, "revoke") {
		t.Errorf("a set secret should still carry the reminder:\n%s", out)
	}
}
