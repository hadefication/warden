package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func chmodEnv(dir string, mode os.FileMode) error {
	return os.Chmod(filepath.Join(dir, ".env"), mode)
}

func TestGetReturnsPublicValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	out, _, code := run(t, "get", "APP_NAME", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if strings.TrimSpace(out) != "Warden" {
		t.Errorf("got %q, want Warden", out)
	}
}

func TestGetRefusesSecretsWithCodeTwo(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=hunter2\n"})
	out, errw, code := run(t, "get", "DB_PASSWORD", "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if strings.Contains(out+errw, "hunter2") {
		t.Fatalf("refusal leaked the value: out=%q err=%q", out, errw)
	}
	if !strings.Contains(errw, "DB_PASSWORD") {
		t.Errorf("the refusal should name the key: %q", errw)
	}
}

func TestGetUnsetKeyExitsOne(t *testing.T) {
	dir := project(t, map[string]string{".env": "A=1\n"})
	if _, _, code := run(t, "get", "NOPE", "--project", dir); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestMissingListsUnfilledKeys(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\n",
		".env.example": "APP_NAME=\nSTRIPE_SECRET=\nMAIL_PASSWORD=\n",
	})
	out, _, code := run(t, "missing", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "STRIPE_SECRET") || !strings.Contains(out, "MAIL_PASSWORD") {
		t.Errorf("got:\n%s", out)
	}
	if strings.Contains(out, "APP_NAME") {
		t.Errorf("APP_NAME is set and must not be listed:\n%s", out)
	}
}

func TestMissingRejectsGlobalScope(t *testing.T) {
	home := project(t, map[string]string{".secrets": "export A=1\n"})
	t.Setenv("HOME", home)
	_, errw, code := run(t, "missing", "--global")
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if !strings.Contains(errw, "global") {
		t.Errorf("the error should explain the scope problem: %q", errw)
	}
}

func TestDoctorReportsEmptyValuesAndDrift(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nSTRIPE_SECRET=\n",
		".env.example": "APP_NAME=\nSTRIPE_SECRET=\nMAIL_PASSWORD=\n",
	})
	out, _, code := run(t, "doctor", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(out, "STRIPE_SECRET") {
		t.Errorf("doctor should flag the empty STRIPE_SECRET:\n%s", out)
	}
	if !strings.Contains(out, "MAIL_PASSWORD") {
		t.Errorf("doctor should flag the missing MAIL_PASSWORD:\n%s", out)
	}
}

func TestDoctorFlagsLooseFilePermissions(t *testing.T) {
	dir := project(t, map[string]string{".env": "A=1\n"})
	if err := chmodEnv(dir, 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, _ := run(t, "doctor", "--project", dir)
	if !strings.Contains(out, "permissions") {
		t.Errorf("doctor should flag world-readable permissions:\n%s", out)
	}
}

func TestDoctorNeverPrintsValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=hunter2\nAPP_NAME=Warden\n"})
	out, errw, _ := run(t, "doctor", "--project", dir)
	if strings.Contains(out+errw, "hunter2") {
		t.Fatalf("doctor leaked a secret value:\n%s%s", out, errw)
	}
}
