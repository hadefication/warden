package query

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// codes reduces a problem list to the thing tests should assert on. Messages are
// prose and will be reworded; codes are the contract.
func codes(ps []Problem) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Code)
	}
	return out
}

func find(t *testing.T, ps []Problem, code string) Problem {
	t.Helper()
	for _, p := range ps {
		if p.Code == code {
			return p
		}
	}
	t.Fatalf("no %q problem in %v", code, codes(ps))
	return Problem{}
}

func TestDoctorFindsNothingWrongWithAHealthyProject(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nDB_PASSWORD=hunter2\n",
		".env.example": "APP_NAME=\nDB_PASSWORD=\n",
	})
	if ps := openProject(t, dir).Doctor(); len(ps) != 0 {
		t.Errorf("healthy project reported %v", codes(ps))
	}
}

func TestDoctorReportsGroupReadablePermissionsAsAnError(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n", ".env.example": "APP_NAME=\n"})
	if err := os.Chmod(filepath.Join(dir, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := find(t, openProject(t, dir).Doctor(), "perms")
	if p.Severity != SeverityError {
		t.Errorf("perms severity = %v, want error — this is the finding with real consequence", p.Severity)
	}
	if p.Key != "" {
		t.Errorf("perms is a file-level problem, got key %q", p.Key)
	}
	if !strings.Contains(p.Fix, "chmod 600") {
		t.Errorf("fix = %q, want a chmod 600 command", p.Fix)
	}
}

func TestDoctorReportsADeclaredButEmptyKeyAsAWarning(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nEMPTY_TOKEN=\n",
		".env.example": "APP_NAME=\nEMPTY_TOKEN=\n",
	})
	p := find(t, openProject(t, dir).Doctor(), "empty")
	if p.Key != "EMPTY_TOKEN" {
		t.Errorf("key = %q, want EMPTY_TOKEN", p.Key)
	}
	if p.Severity != SeverityWarn {
		t.Errorf("empty severity = %v, want warn", p.Severity)
	}
	if !strings.Contains(p.Fix, "--secret") {
		t.Errorf("fix = %q, want the prompted-write command for a secret key", p.Fix)
	}
}

func TestDoctorReportsDriftAgainstTheExampleFile(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\n",
		".env.example": "APP_NAME=\nNEVER_SET=\n",
	})
	p := find(t, openProject(t, dir).Doctor(), "drift")
	if p.Key != "NEVER_SET" {
		t.Errorf("key = %q, want NEVER_SET", p.Key)
	}
	if p.Severity != SeverityWarn {
		t.Errorf("drift severity = %v, want warn", p.Severity)
	}
}

// The v1 implementation dropped Missing's error, so a project with no example
// file looked identical to one whose example file was fully satisfied.
func TestDoctorSaysWhenThereIsNoExampleFileToCompareAgainst(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	p := find(t, openProject(t, dir).Doctor(), "no-example")
	if p.Severity != SeverityInfo {
		t.Errorf("no-example severity = %v, want info — it is not a defect", p.Severity)
	}
}

func TestDoctorInGlobalScopeSkipsTheExampleFileChecks(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte("export GH_TOKEN=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := Open(Scope{Global: true, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range codes(q.Doctor()) {
		if c == "drift" || c == "no-example" {
			t.Errorf("~/.secrets has no .env.example counterpart; got %q", c)
		}
	}
}

// A key that is declared-but-empty in .env and also listed in .env.example
// satisfies both checks. Reporting it twice, with the same fix, is noise that
// makes a long doctor run harder to read than it should be.
func TestDoctorReportsEachKeyOnce(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nEMPTY_TOKEN=\n",
		".env.example": "APP_NAME=\nEMPTY_TOKEN=\n",
	})
	ps := openProject(t, dir).Doctor()
	if len(ps) != 1 {
		t.Fatalf("got %d problems %v, want 1 — the empty check already covers this key", len(ps), codes(ps))
	}
	if ps[0].Code != "empty" {
		t.Errorf("code = %q, want the more specific %q", ps[0].Code, "empty")
	}
}
