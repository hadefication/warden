package store

import (
	"os"
	"path/filepath"
	"testing"
)

func seed(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOpenDotenvFindsFileInStartDir(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "APP_NAME=Warden\n")
	s, err := OpenDotenv(dir)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := s.Get("APP_NAME")
	if !ok || v.Expose() != "Warden" {
		t.Errorf("Get(APP_NAME) = %q ok=%v", v.Expose(), ok)
	}
}

func TestOpenDotenvWalksUpward(t *testing.T) {
	root := t.TempDir()
	seed(t, root, ".env", "APP_NAME=Warden\n")
	deep := filepath.Join(root, "app", "Http", "Controllers")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := OpenDotenv(deep)
	if err != nil {
		t.Fatal(err)
	}
	if s.Path() != filepath.Join(root, ".env") {
		t.Errorf("Path() = %s, want the root .env", s.Path())
	}
}

func TestOpenDotenvStopsWithoutAFile(t *testing.T) {
	if _, err := OpenDotenv(t.TempDir()); err != ErrNoFile {
		t.Errorf("err = %v, want ErrNoFile", err)
	}
}

func TestGetReturnsSecretThatDoesNotPrint(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "STRIPE_SECRET=sk_live_canary123\n")
	s, _ := OpenDotenv(dir)
	v, _ := s.Get("STRIPE_SECRET")
	if got := v.String(); got == "sk_live_canary123" {
		t.Error("store value must be a redacting Secret")
	}
	if v.Expose() != "sk_live_canary123" {
		t.Error("Expose must still yield the real value")
	}
}

func TestGetMissingKey(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "A=1\n")
	s, _ := OpenDotenv(dir)
	if _, ok := s.Get("NOPE"); ok {
		t.Error("missing key must report ok=false")
	}
}

func TestKeysListsEveryAssignment(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "A=1\n# c\nB=2\n")
	s, _ := OpenDotenv(dir)
	got := s.Keys()
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Errorf("Keys() = %v, want [A B]", got)
	}
}

func TestSetPersists(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "A=1\n")
	s, _ := OpenDotenv(dir)
	if err := s.Set("A", "2"); err != nil {
		t.Fatal(err)
	}
	reopened, _ := OpenDotenv(dir)
	v, _ := reopened.Get("A")
	if v.Expose() != "2" {
		t.Errorf("after Set, A = %q, want 2", v.Expose())
	}
}

func TestExampleKeys(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "A=1\n")
	seed(t, dir, ".env.example", "A=\nB=\n# comment\nC=\n")
	got, err := ExampleKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != "A" || got[2] != "C" {
		t.Errorf("ExampleKeys() = %v, want [A B C]", got)
	}
}

func TestExampleKeysMissingFile(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "A=1\n")
	if _, err := ExampleKeys(dir); err != ErrNoFile {
		t.Errorf("err = %v, want ErrNoFile", err)
	}
}
