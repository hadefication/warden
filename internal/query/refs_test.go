package query

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func refKeys(rs []Reference) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Key] = true
	}
	return out
}

func TestRefsReportsKeysTheCodeReadsAndTheFileDoesNotSet(t *testing.T) {
	dir := project(t, map[string]string{
		".env":       "APP_NAME=Warden\n",
		"Mailer.php": "env('MAILGUN_SECRET');\nenv('APP_NAME');\n",
	})
	rep, err := openProject(t, dir).Refs(RefOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !refKeys(rep.Undeclared)["MAILGUN_SECRET"] {
		t.Errorf("MAILGUN_SECRET should be undeclared, got %v", refKeys(rep.Undeclared))
	}
	if refKeys(rep.Undeclared)["APP_NAME"] {
		t.Error("APP_NAME is set — it is not undeclared")
	}
}

func TestRefsReportsKeysNothingReferences(t *testing.T) {
	dir := project(t, map[string]string{
		".env":       "APP_NAME=Warden\nOLD_SENTRY_DSN=https://x@example.test/1\n",
		"Mailer.php": "env('APP_NAME');\n",
	})
	rep, err := openProject(t, dir).Refs(RefOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var unused []string
	for _, r := range rep.Unused {
		unused = append(unused, r.Key)
	}
	if len(unused) != 1 || unused[0] != "OLD_SENTRY_DSN" {
		t.Errorf("unused = %v, want [OLD_SENTRY_DSN]", unused)
	}
}

// A weak reference cannot declare a key, but it is ample proof one is used.
func TestAKeyReferencedOnlyByInterpolationIsNotUnused(t *testing.T) {
	dir := project(t, map[string]string{
		".env":               "API_BASE=https://example.test\n",
		"docker-compose.yml": "environment:\n  API: ${API_BASE}\n",
	})
	rep, err := openProject(t, dir).Refs(RefOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Unused) != 0 {
		t.Errorf("unused = %v, want none", rep.Unused)
	}
	if len(rep.Undeclared) != 0 {
		t.Errorf("interpolation must never declare: %v", refKeys(rep.Undeclared))
	}
}

func TestRefsIsProjectOnly(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".secrets"), []byte("export A=b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	q, err := Open(Scope{Global: true, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Refs(RefOptions{}); !errors.Is(err, ErrGlobalUnsupported) {
		t.Errorf("err = %v, want ErrGlobalUnsupported", err)
	}
}

func TestDoctorOnlyChecksReferencesWhenAsked(t *testing.T) {
	dir := project(t, map[string]string{
		".env":       "APP_NAME=Warden\n",
		"Mailer.php": "env('MAILGUN_SECRET');\n",
	})
	q := openProject(t, dir)

	for _, c := range codes(q.Doctor()) {
		if c == "undeclared" {
			t.Fatal("walking the tree costs real time; plain doctor must not do it")
		}
	}

	p := find(t, q.DoctorWithRefs(RefOptions{}), "undeclared")
	if p.Key != "MAILGUN_SECRET" {
		t.Errorf("key = %q, want MAILGUN_SECRET", p.Key)
	}
	if p.Severity != SeverityError {
		t.Errorf("severity = %v, want error — the code needs it and it is absent now", p.Severity)
	}
}

// Static analysis cannot see a key built at runtime, so this finding is advisory
// and must never gate a build.
func TestAnUnreferencedKeyIsOnlyInformational(t *testing.T) {
	dir := project(t, map[string]string{
		".env":       "APP_NAME=Warden\nOLD_KEY=x\n",
		"Mailer.php": "env('APP_NAME');\n",
	})
	p := find(t, openProject(t, dir).DoctorWithRefs(RefOptions{}), "unreferenced")
	if p.Severity != SeverityInfo {
		t.Errorf("severity = %v, want info", p.Severity)
	}
}
