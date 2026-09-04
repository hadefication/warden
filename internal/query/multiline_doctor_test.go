package query

import (
	"strings"
	"testing"
)

func TestDoctorReportsAMultiLineValueAsInfo(t *testing.T) {
	// warden now reads a double-quoted \n as a newline, the way the app's dotenv
	// loader does. That is a change in meaning for files already on disk, so the
	// affected keys are worth naming — but as information, not a defect. warden
	// writes these itself now, and a warning nobody can clear is one people learn
	// to scroll past.
	dir := project(t, map[string]string{".env": `TLS_KEY="line one\nline two"` + "\n"})

	p, ok := findProblem(openProject(t, dir).Doctor(), "multiline")
	if !ok {
		t.Fatal("doctor did not mention the multi-line value")
	}
	if p.Key != "TLS_KEY" {
		t.Errorf("Key = %q", p.Key)
	}
	if p.Severity != SeverityInfo {
		t.Errorf("Severity = %v, want info", p.Severity)
	}
	if strings.Contains(p.Message+p.Fix, "line one") {
		t.Error("the finding carried the value")
	}
}

func TestDoctorSaysNothingAboutSingleLineValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nDB_PASSWORD=hunter2\n"})
	if _, ok := findProblem(openProject(t, dir).Doctor(), "multiline"); ok {
		t.Error("doctor invented a multi-line value")
	}
}

func TestDoctorDoesNotTreatALiteralBackslashNAsMultiLine(t *testing.T) {
	// Single quotes carry no escapes, so this really is a literal backslash-n.
	dir := project(t, map[string]string{".env": `SEP='a\nb'` + "\n"})
	if _, ok := findProblem(openProject(t, dir).Doctor(), "multiline"); ok {
		t.Error("a single-quoted literal was read as a newline")
	}
}
