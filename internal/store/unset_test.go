package store

import (
	"path/filepath"
	"testing"
)

func TestUnsetRemovesFromADotenvStore(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "APP_NAME=Warden\nGH_TOKEN=abc\n")
	st, err := OpenDotenv(dir)
	if err != nil {
		t.Fatal(err)
	}

	n, err := st.Unset("GH_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("removed %d, want 1", n)
	}

	reopened, err := OpenDotenv(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("GH_TOKEN"); ok {
		t.Error("GH_TOKEN survived a reopen — the removal was not persisted")
	}
	if _, ok := reopened.Get("APP_NAME"); !ok {
		t.Error("APP_NAME should be untouched")
	}
}

func TestUnsetRemovesFromTheSecretsFile(t *testing.T) {
	home := t.TempDir()
	seed(t, home, ".secrets", "export GH_TOKEN=abc\nexport OTHER=keep\n")
	st, err := OpenSecrets(home)
	if err != nil {
		t.Fatal(err)
	}

	if n, err := st.Unset("GH_TOKEN"); err != nil || n != 1 {
		t.Fatalf("Unset = %d, %v; want 1, nil", n, err)
	}
	reopened, err := OpenSecrets(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("GH_TOKEN"); ok {
		t.Error("GH_TOKEN survived")
	}
	if _, ok := reopened.Get("OTHER"); !ok {
		t.Error("OTHER should be untouched")
	}
	_ = filepath.Join
}

func TestUnsetReportsZeroForAnAbsentKey(t *testing.T) {
	dir := t.TempDir()
	seed(t, dir, ".env", "APP_NAME=Warden\n")
	st, err := OpenDotenv(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.Unset("ABSENT"); err != nil || n != 0 {
		t.Errorf("Unset = %d, %v; want 0, nil", n, err)
	}
}
