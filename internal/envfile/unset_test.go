package envfile

import (
	"os"
	"testing"
)

func reread(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUnsetRemovesTheAssignmentAndNothingElse(t *testing.T) {
	path := write(t, ".env", "# leading comment\nAPP_NAME=Warden\n\n# about the token\nGH_TOKEN=abc\nDB_HOST=127.0.0.1\n")
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if n := f.Unset("GH_TOKEN"); n != 1 {
		t.Errorf("removed %d lines, want 1", n)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}

	// The comment above a removed line stays: warden cannot know whether it
	// described the key or the section, and guessing wrong deletes documentation.
	want := "# leading comment\nAPP_NAME=Warden\n\n# about the token\nDB_HOST=127.0.0.1\n"
	if got := reread(t, path); got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

// Get reads the last assignment, as the shell does. Removing only that one would
// resurrect an older value while reporting success — a live credential left
// behind by an operation that looked like it worked.
func TestUnsetRemovesEveryAssignmentOfTheKey(t *testing.T) {
	path := write(t, ".env", "GH_TOKEN=old\nAPP_NAME=Warden\nGH_TOKEN=new\n")
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if n := f.Unset("GH_TOKEN"); n != 2 {
		t.Errorf("removed %d lines, want 2", n)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if got := reread(t, path); got != "APP_NAME=Warden\n" {
		t.Errorf("got %q", got)
	}

	reparsed, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reparsed.Get("GH_TOKEN"); ok {
		t.Error("GH_TOKEN survived the removal")
	}
}

func TestUnsetOfAnAbsentKeyChangesNothing(t *testing.T) {
	const body = "APP_NAME=Warden\n"
	path := write(t, ".env", body)
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if n := f.Unset("ABSENT"); n != 0 {
		t.Errorf("removed %d lines, want 0", n)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if got := reread(t, path); got != body {
		t.Errorf("got %q, want %q", got, body)
	}
}

func TestUnsetPreservesCRLFAndMissingTrailingNewline(t *testing.T) {
	path := write(t, ".env", "APP_NAME=Warden\r\nGH_TOKEN=abc\r\nDB_HOST=local")
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.Unset("GH_TOKEN")
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if got := reread(t, path); got != "APP_NAME=Warden\r\nDB_HOST=local" {
		t.Errorf("got %q", got)
	}
}

func TestUnsetRemovesExportedAssignments(t *testing.T) {
	path := write(t, ".env", "export GH_TOKEN=abc\nexport APP_NAME=Warden\n")
	f, err := Parse(path, Options{AllowExport: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.Unset("GH_TOKEN"); n != 1 {
		t.Errorf("removed %d lines, want 1", n)
	}
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if got := reread(t, path); got != "export APP_NAME=Warden\n" {
		t.Errorf("got %q", got)
	}
}

// Removing the last assignment should leave an empty file, not a lone newline.
// The trailing-newline rule exists to preserve the shape of a file with content
// in it; there is no content left to shape.
func TestUnsetOfTheOnlyLineLeavesAnEmptyFile(t *testing.T) {
	path := write(t, ".env", "GH_TOKEN=abc\n")
	f, err := Parse(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.Unset("GH_TOKEN")
	if err := f.Save(); err != nil {
		t.Fatal(err)
	}
	if got := reread(t, path); got != "" {
		t.Errorf("got %q, want an empty file", got)
	}
}
