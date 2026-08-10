package query

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/classify"
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

func openProject(t *testing.T, dir string) *Q {
	t.Helper()
	q, err := Open(Scope{Dir: dir, Home: dir})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestHasTreatsEmptyAsUnset(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nEMPTY=\n"})
	q := openProject(t, dir)
	if !q.Has("APP_NAME") {
		t.Error("APP_NAME should be set")
	}
	if q.Has("EMPTY") {
		t.Error("a declared-but-empty key must not count as set")
	}
	if q.Has("ABSENT") {
		t.Error("an absent key must not count as set")
	}
}

func TestHasWorksForSecretsToo(t *testing.T) {
	dir := project(t, map[string]string{".env": "STRIPE_SECRET=sk_live_abc\n"})
	if !openProject(t, dir).Has("STRIPE_SECRET") {
		t.Error("Has must answer for secret keys — that is the whole point")
	}
}

func TestListClassifiesWithoutReturningValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nDB_PASSWORD=hunter2\nEMPTY_TOKEN=\n"})
	rows := openProject(t, dir).List()
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	want := map[string]struct {
		class classify.Class
		set   bool
	}{
		"APP_NAME":    {classify.Public, true},
		"DB_PASSWORD": {classify.Secret, true},
		"EMPTY_TOKEN": {classify.Secret, false},
	}
	for _, r := range rows {
		w, ok := want[r.Key]
		if !ok {
			t.Errorf("unexpected key %s", r.Key)
			continue
		}
		if r.Class != w.class || r.Set != w.set {
			t.Errorf("%s = %s/set=%v, want %s/set=%v", r.Key, r.Class, r.Set, w.class, w.set)
		}
	}
}

func TestGetReturnsPublicValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	got, err := openProject(t, dir).Get("APP_NAME")
	if err != nil {
		t.Fatal(err)
	}
	if got != "Warden" {
		t.Errorf("Get(APP_NAME) = %q, want Warden", got)
	}
}

func TestGetRefusesSecrets(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=hunter2\n"})
	got, err := openProject(t, dir).Get("DB_PASSWORD")
	if !errors.Is(err, ErrSecret) {
		t.Errorf("err = %v, want ErrSecret", err)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatal("a refused Get leaked the value in its return")
	}
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Fatal("a refused Get leaked the value in its error")
	}
}

func TestGetAbsentKey(t *testing.T) {
	dir := project(t, map[string]string{".env": "A=1\n"})
	if _, err := openProject(t, dir).Get("NOPE"); !errors.Is(err, ErrNotSet) {
		t.Errorf("err = %v, want ErrNotSet", err)
	}
}

func TestMissingDiffsAgainstExample(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nDB_HOST=localhost\n",
		".env.example": "APP_NAME=\nDB_HOST=\nSTRIPE_SECRET=\nMAIL_PASSWORD=\n",
	})
	got, err := openProject(t, dir).Missing()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "STRIPE_SECRET" || got[1] != "MAIL_PASSWORD" {
		t.Errorf("Missing() = %v, want [STRIPE_SECRET MAIL_PASSWORD]", got)
	}
}

func TestMissingCountsEmptyValuesAsMissing(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nSTRIPE_SECRET=\n",
		".env.example": "APP_NAME=\nSTRIPE_SECRET=\n",
	})
	got, _ := openProject(t, dir).Missing()
	if len(got) != 1 || got[0] != "STRIPE_SECRET" {
		t.Errorf("Missing() = %v, want [STRIPE_SECRET] — declared but empty is missing", got)
	}
}

func TestMissingIsProjectOnly(t *testing.T) {
	home := project(t, map[string]string{".secrets": "export GH_TOKEN=abc\n"})
	q, err := Open(Scope{Global: true, Dir: home, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Missing(); !errors.Is(err, ErrGlobalUnsupported) {
		t.Errorf("err = %v, want ErrGlobalUnsupported", err)
	}
}

func TestGlobalScopeReadsSecretsFile(t *testing.T) {
	home := project(t, map[string]string{".secrets": "export GH_TOKEN=ghp_abc\n"})
	q, err := Open(Scope{Global: true, Dir: home, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Has("GH_TOKEN") {
		t.Error("global scope should see GH_TOKEN")
	}
	if got := q.Classify("GH_TOKEN"); got.Class != classify.Secret {
		t.Errorf("GH_TOKEN = %s, want secret", got.Class)
	}
}

func TestClassifyExplainsItself(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_URL=https://admin:pw@host\n"})
	got := openProject(t, dir).Classify("APP_URL")
	if got.Class != classify.Secret || got.Rule != "shape:url-userinfo" {
		t.Errorf("got %s (%s), want secret (shape:url-userinfo)", got.Class, got.Rule)
	}
}

func TestSchemaIsLoadedFromTheProjectDirectory(t *testing.T) {
	dir := project(t, map[string]string{
		".env":        "MY_PUBLIC_KEY=abc\n",
		".env.schema": "MY_PUBLIC_KEY=public\n",
	})
	q := openProject(t, dir)
	if got := q.Classify("MY_PUBLIC_KEY"); got.Class != classify.Public {
		t.Errorf("got %s (%s), want public via schema", got.Class, got.Rule)
	}
	if _, err := q.Get("MY_PUBLIC_KEY"); err != nil {
		t.Errorf("a schema-public key must be readable: %v", err)
	}
}
