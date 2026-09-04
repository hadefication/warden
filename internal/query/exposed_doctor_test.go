package query

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/exposure"
)

// findProblem returns the first problem with the given code.
func findProblem(ps []Problem, code string) (Problem, bool) {
	for _, p := range ps {
		if p.Code == code {
			return p, true
		}
	}
	return Problem{}, false
}

func TestDoctorReportsAnExposedKey(t *testing.T) {
	// The exposure record is what makes --exposed honest: a message printed once
	// scrolls away, so doctor keeps saying it until the key is rotated.
	dir := project(t, map[string]string{".env": "CF_API_TOKEN=abc123\n"})
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := exposure.Record(dir, canonical, "CF_API_TOKEN"); err != nil {
		t.Fatal(err)
	}

	p, ok := findProblem(openProject(t, dir).Doctor(), "exposed")
	if !ok {
		t.Fatal("doctor did not report the exposed key")
	}
	if p.Key != "CF_API_TOKEN" {
		t.Errorf("Key = %q", p.Key)
	}
	if p.Severity != SeverityWarn {
		t.Errorf("Severity = %v, want warn", p.Severity)
	}
	if !strings.Contains(strings.ToLower(p.Message+p.Fix), "rotate") {
		t.Errorf("the finding should say to rotate: %+v", p)
	}
	if strings.Contains(p.Message+p.Fix, "abc123") {
		t.Error("the finding carried the value")
	}
}

func TestDoctorSaysNothingWhenNothingWasExposed(t *testing.T) {
	dir := project(t, map[string]string{".env": "CF_API_TOKEN=abc123\n"})
	if _, ok := findProblem(openProject(t, dir).Doctor(), "exposed"); ok {
		t.Error("doctor invented an exposure")
	}
}
