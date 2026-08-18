package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// warnOnly has an empty key and drift, and no error-severity problem.
func warnOnly(t *testing.T) string {
	return project(t, map[string]string{
		".env":         "APP_NAME=Warden\nEMPTY_TOKEN=\n",
		".env.example": "APP_NAME=\nEMPTY_TOKEN=\nNEVER_SET=\n",
	})
}

func TestDoctorWithoutStrictStillExitsZero(t *testing.T) {
	if _, _, code := run(t, "doctor", "--project", warnOnly(t)); code != 0 {
		t.Errorf("code = %d, want 0 — bare doctor reports, it does not gate", code)
	}
}

func TestDoctorStrictFailsOnWarnings(t *testing.T) {
	if _, _, code := run(t, "doctor", "--strict", "--project", warnOnly(t)); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestDoctorStrictErrorIgnoresWarnings(t *testing.T) {
	if _, _, code := run(t, "doctor", "--strict=error", "--project", warnOnly(t)); code != 0 {
		t.Errorf("code = %d, want 0 — warn is below the error threshold", code)
	}
}

func TestDoctorStrictErrorFailsOnPermissions(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n", ".env.example": "APP_NAME=\n"})
	if err := os.Chmod(filepath.Join(dir, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, code := run(t, "doctor", "--strict=error", "--project", dir); code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
}

func TestDoctorStrictPassesACleanProject(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n", ".env.example": "APP_NAME=\n"})
	if _, _, code := run(t, "doctor", "--strict", "--project", dir); code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

// An info problem is not a defect and must not gate anything, or a fresh project
// with no example file could never pass --strict.
func TestDoctorStrictIgnoresInfoProblems(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	out, _, code := run(t, "doctor", "--strict", "--project", dir)
	if code != 0 {
		t.Errorf("code = %d, want 0; output was:\n%s", code, out)
	}
}

// A missing .env is warden failing, not the project failing.
func TestDoctorStrictKeepsErrorsDistinctFromFindings(t *testing.T) {
	if _, _, code := run(t, "doctor", "--strict", "--project", "/nonexistent"); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
}

func TestDoctorRejectsAnUnknownStrictLevel(t *testing.T) {
	if _, _, code := run(t, "doctor", "--strict=loud", "--project", warnOnly(t)); code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
}

func TestDoctorJSONCarriesCodesAndSeverities(t *testing.T) {
	out, _, _ := run(t, "doctor", "--json", "--project", warnOnly(t))

	var got []struct {
		Code     string `json:"code"`
		Key      string `json:"key"`
		Severity string `json:"severity"`
		Fix      string `json:"fix"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("doctor --json is not an array of problems: %v\n%s", err, out)
	}
	seen := map[string]string{}
	for _, p := range got {
		seen[p.Code] = p.Severity
	}
	if seen["empty"] != "warn" {
		t.Errorf("empty severity = %q, want warn (codes seen: %v)", seen["empty"], seen)
	}
	if seen["drift"] != "warn" {
		t.Errorf("drift severity = %q, want warn (codes seen: %v)", seen["drift"], seen)
	}
}

func TestDoctorTextOutputNamesTheFix(t *testing.T) {
	out, _, _ := run(t, "doctor", "--project", warnOnly(t))
	if !strings.Contains(out, "warden set --secret EMPTY_TOKEN") {
		t.Errorf("output should name the command that fixes it:\n%s", out)
	}
}
