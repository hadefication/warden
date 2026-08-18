package refs

import (
	"os"
	"path/filepath"
	"testing"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func keys(rs []Reference) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Key] = true
	}
	return out
}

func strongKeys(rs []Reference) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		if !r.Weak {
			out[r.Key] = true
		}
	}
	return out
}

func TestScanFindsReferencesInEverySupportedLanguage(t *testing.T) {
	root := tree(t, map[string]string{
		"app/Mailer.php": "$k = env('MAILGUN_SECRET');\n$j = env(\"PHP_DOUBLE\");\n",
		"src/index.js":   "const a = process.env.NODE_ONE;\nconst b = process.env['NODE_TWO'];\n",
		"src/vite.js":    "const c = import.meta.env.VITE_THREE;\n",
		"main.go":        "v := os.Getenv(\"GO_ONE\")\nw, ok := os.LookupEnv(\"GO_TWO\")\n",
		"run.py":         "a = os.environ['PY_ONE']\nb = os.environ.get('PY_TWO')\nc = getenv('PY_THREE')\n",
	})

	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	found := strongKeys(got)
	for _, want := range []string{
		"MAILGUN_SECRET", "PHP_DOUBLE", "NODE_ONE", "NODE_TWO", "VITE_THREE",
		"GO_ONE", "GO_TWO", "PY_ONE", "PY_TWO", "PY_THREE",
	} {
		if !found[want] {
			t.Errorf("missed %s", want)
		}
	}
}

func TestScanRecordsWhereEachReferenceIs(t *testing.T) {
	root := tree(t, map[string]string{"app/Mailer.php": "<?php\n\n$k = env('MAILGUN_SECRET');\n"})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d references, want 1", len(got))
	}
	if got[0].Path != "app/Mailer.php" {
		t.Errorf("path = %q, want a path relative to the root", got[0].Path)
	}
	if got[0].Line != 3 {
		t.Errorf("line = %d, want 3", got[0].Line)
	}
}

// ${FOO} is far too common to treat as a declaration: every ${HOME} in a
// Dockerfile would become a missing key. Those forms can only confirm that a key
// warden already knows about is used.
func TestShellAndYAMLFormsAreWeak(t *testing.T) {
	root := tree(t, map[string]string{
		"docker-compose.yml": "environment:\n  API: ${API_BASE}\n",
		"deploy.sh":          "echo $DEPLOY_TARGET\n",
	})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(strongKeys(got)) != 0 {
		t.Errorf("interpolation must not declare anything: %v", strongKeys(got))
	}
	if !keys(got)["API_BASE"] || !keys(got)["DEPLOY_TARGET"] {
		t.Errorf("interpolation should still mark a key as used, got %v", keys(got))
	}
}

func TestScanDoesNotMatchLongerFunctionNames(t *testing.T) {
	root := tree(t, map[string]string{"a.php": "envelope('NOT_A_KEY');\nmy_getenv('ALSO_NOT');\n"})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(strongKeys(got)) != 0 {
		t.Errorf("got %v, want nothing — the call has to be env(), not a word ending in env", strongKeys(got))
	}
}

// Pinned rather than fixed: a key built at runtime cannot be seen by any amount
// of regex, and this is why "unused" is advisory and never drives a deletion.
func TestADynamicallyBuiltKeyIsInvisible(t *testing.T) {
	root := tree(t, map[string]string{"a.php": "env(\"STRIPE_{$mode}_SECRET\");\nenv($name);\n"})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing", keys(got))
	}
}

// Comments are not parsed. Doing it properly needs a parser per language, and
// pretending otherwise would be worse than the false positive.
func TestAReferenceInACommentStillCounts(t *testing.T) {
	root := tree(t, map[string]string{"a.php": "// env('COMMENTED_KEY') is read elsewhere\n"})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if !strongKeys(got)["COMMENTED_KEY"] {
		t.Error("a commented reference is still counted; this test pins that")
	}
}

func TestScanSkipsDependencyDirectories(t *testing.T) {
	root := tree(t, map[string]string{
		"vendor/pkg/a.php":  "env('VENDOR_KEY');\n",
		"node_modules/b.js": "process.env.MODULE_KEY;\n",
		"app/c.php":         "env('REAL_KEY');\n",
	})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	found := keys(got)
	if found["VENDOR_KEY"] || found["MODULE_KEY"] {
		t.Errorf("dependency directories must be skipped, got %v", found)
	}
	if !found["REAL_KEY"] {
		t.Error("missed REAL_KEY")
	}
}

func TestScanIgnoresTheEnvFilesThemselves(t *testing.T) {
	root := tree(t, map[string]string{
		".env":         "APP_NAME=Warden\n",
		".env.example": "APP_NAME=\n",
		"a.php":        "env('REAL_KEY');\n",
	})
	got, err := Scan(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if keys(got)["APP_NAME"] {
		t.Error("a key's own declaration is not a reference to it")
	}
}

// A file warden could not read is a hole in the "unused" answer: a key
// referenced only there looks dead. Silently reduced coverage reads as complete
// coverage, so the count has to come back to the caller.
func TestScanReportsFilesItCouldNotRead(t *testing.T) {
	root := tree(t, map[string]string{
		"app/a.php": "env('REAL_KEY');\n",
		"logo.bin":  "\x00\x01binary\x00",
	})
	big := filepath.Join(root, "bundle.js")
	if err := os.WriteFile(big, make([]byte, maxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanTree(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 2 {
		t.Errorf("skipped = %v, want the binary and the oversized file", res.Skipped)
	}
	if !strongKeys(res.References)["REAL_KEY"] {
		t.Error("a skipped file must not stop the rest of the walk")
	}
}
