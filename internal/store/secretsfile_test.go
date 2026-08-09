package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenSecretsReadsExportedAndBareAssignments(t *testing.T) {
	home := t.TempDir()
	seed(t, home, ".secrets", "export GH_TOKEN=ghp_abc\nOPENAI_KEY=sk-def\n")
	s, err := OpenSecrets(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, want string }{
		{"GH_TOKEN", "ghp_abc"},
		{"OPENAI_KEY", "sk-def"},
	} {
		v, ok := s.Get(tc.key)
		if !ok || v.Expose() != tc.want {
			t.Errorf("%s = %q ok=%v, want %q", tc.key, v.Expose(), ok, tc.want)
		}
	}
}

// The whole reason this file is parsed rather than sourced: a value containing
// a command substitution must be inert text, never something that runs.
func TestCommandSubstitutionIsInertText(t *testing.T) {
	home := t.TempDir()
	marker := filepath.Join(home, "SHOULD_NOT_EXIST")
	seed(t, home, ".secrets", "export EVIL=$(touch "+marker+")\nexport WHO=$(whoami)\n")

	s, err := OpenSecrets(home)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := s.Get("WHO")
	if v.Expose() != "$(whoami)" {
		t.Errorf("WHO = %q, want the literal text $(whoami)", v.Expose())
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("parsing executed a command substitution — the file was sourced")
	}
}

func TestOpenSecretsMissingFile(t *testing.T) {
	if _, err := OpenSecrets(t.TempDir()); err != ErrNoFile {
		t.Errorf("err = %v, want ErrNoFile", err)
	}
}

func TestSecretsSetPreservesExportPrefix(t *testing.T) {
	home := t.TempDir()
	seed(t, home, ".secrets", "export GH_TOKEN=old\n")
	s, _ := OpenSecrets(home)
	if err := s.Set("GH_TOKEN", "new"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(home, ".secrets"))
	if string(got) != "export GH_TOKEN=new\n" {
		t.Errorf("got %q, want the export prefix preserved", got)
	}
}

func TestSecretsPathIsReported(t *testing.T) {
	home := t.TempDir()
	seed(t, home, ".secrets", "A=1\n")
	s, _ := OpenSecrets(home)
	if s.Path() != filepath.Join(home, ".secrets") {
		t.Errorf("Path() = %s", s.Path())
	}
}
