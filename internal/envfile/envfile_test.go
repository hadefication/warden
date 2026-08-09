package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseReadsKeysAndValues(t *testing.T) {
	p := write(t, ".env", "# a comment\nAPP_NAME=Warden\n\nDB_PORT=3306\nQUOTED=\"hello world\"\nSINGLE='literal'\nEMPTY=\n")
	f, err := Parse(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ key, want string }{
		{"APP_NAME", "Warden"},
		{"DB_PORT", "3306"},
		{"QUOTED", "hello world"},
		{"SINGLE", "literal"},
		{"EMPTY", ""},
	} {
		got, ok := f.Get(tc.key)
		if !ok {
			t.Errorf("%s: not found", tc.key)
			continue
		}
		if got != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, got, tc.want)
		}
	}
	if _, ok := f.Get("NOPE"); ok {
		t.Error("NOPE should not be found")
	}
}

func TestKeysPreservesFileOrder(t *testing.T) {
	p := write(t, ".env", "B=2\nA=1\nC=3\n")
	f, _ := Parse(p, Options{})
	got := f.Keys()
	want := []string{"B", "A", "C"}
	if len(got) != len(want) {
		t.Fatalf("Keys() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Keys() = %v, want %v", got, want)
		}
	}
}

func TestSetExistingKeyPreservesEverythingElse(t *testing.T) {
	body := "# leading comment\nAPP_NAME=Old  # trailing\n\n# section\nDB_PORT=3306\n"
	p := write(t, ".env", body)
	f, _ := Parse(p, Options{})
	f.Set("APP_NAME", "New")
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	want := "# leading comment\nAPP_NAME=New\n\n# section\nDB_PORT=3306\n"
	if string(got) != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestSetNewKeyAppends(t *testing.T) {
	p := write(t, ".env", "A=1\n")
	f, _ := Parse(p, Options{})
	f.Set("B", "2")
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "A=1\nB=2\n" {
		t.Errorf("got %q", got)
	}
}

func TestSaveRoundTripsUnmodifiedFileByteForByte(t *testing.T) {
	body := "# comment\nexport A=1\n\nB=\"two words\"\nC='three'\n# trailing comment\n"
	p := write(t, ".env", body)
	f, _ := Parse(p, Options{AllowExport: true})
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != body {
		t.Errorf("round trip changed the file:\ngot:  %q\nwant: %q", got, body)
	}
}

func TestSavePreservesMissingTrailingNewline(t *testing.T) {
	p := write(t, ".env", "A=1")
	f, _ := Parse(p, Options{})
	f.Save()
	got, _ := os.ReadFile(p)
	if string(got) != "A=1" {
		t.Errorf("got %q, want %q", got, "A=1")
	}
}

func TestSavePreservesCRLF(t *testing.T) {
	p := write(t, ".env", "A=1\r\nB=2\r\n")
	f, _ := Parse(p, Options{})
	f.Set("A", "9")
	f.Save()
	got, _ := os.ReadFile(p)
	if string(got) != "A=9\r\nB=2\r\n" {
		t.Errorf("got %q", got)
	}
}

func TestSavePreservesFileMode(t *testing.T) {
	p := write(t, ".env", "A=1\n")
	os.Chmod(p, 0o600)
	f, _ := Parse(p, Options{})
	f.Set("A", "2")
	f.Save()
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", st.Mode().Perm())
	}
}

func TestSetQuotesValuesThatNeedIt(t *testing.T) {
	p := write(t, ".env", "A=1\n")
	f, _ := Parse(p, Options{})
	f.Set("A", "two words")
	f.Save()
	got, _ := os.ReadFile(p)
	if string(got) != "A=\"two words\"\n" {
		t.Errorf("got %q", got)
	}
}

func TestExportPrefixOnlyHonouredWhenAllowed(t *testing.T) {
	p := write(t, ".secrets", "export TOKEN=abc\n")

	f, _ := Parse(p, Options{AllowExport: true})
	if v, ok := f.Get("TOKEN"); !ok || v != "abc" {
		t.Errorf("with AllowExport: got %q ok=%v, want \"abc\" true", v, ok)
	}

	g, _ := Parse(p, Options{})
	if _, ok := g.Get("TOKEN"); ok {
		t.Error("without AllowExport the export line must not parse as a key")
	}
}

func TestExportPrefixSurvivesSet(t *testing.T) {
	p := write(t, ".secrets", "export TOKEN=abc\n")
	f, _ := Parse(p, Options{AllowExport: true})
	f.Set("TOKEN", "xyz")
	f.Save()
	got, _ := os.ReadFile(p)
	if string(got) != "export TOKEN=xyz\n" {
		t.Errorf("got %q, want export prefix preserved", got)
	}
}

func TestParseRefusesConflictMarkers(t *testing.T) {
	p := write(t, ".env", "A=1\n<<<<<<< HEAD\nB=2\n=======\nB=3\n>>>>>>> other\n")
	if _, err := Parse(p, Options{}); err != ErrConflictMarkers {
		t.Errorf("err = %v, want ErrConflictMarkers", err)
	}
}

func TestParseMissingFileReturnsNotExist(t *testing.T) {
	_, err := Parse(filepath.Join(t.TempDir(), "nope"), Options{})
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want a not-exist error", err)
	}
}
