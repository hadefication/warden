// Package refs finds where a codebase reads environment variables.
//
// It deals in key names and file locations, and never in values: it has no
// dependency on internal/store, internal/secret, or anything that could hand it
// one. That is what makes it the cheapest analysis in the tool to trust — the
// worst a bug here can do is name the wrong file.
package refs

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Reference is one place a key is read.
type Reference struct {
	Key  string `json:"key"`
	Path string `json:"path"`
	Line int    `json:"line"`
	// Weak marks a form too common to treat as a declaration — shell and YAML
	// interpolation. A weak reference proves a known key is used; it never
	// asserts that a key ought to exist.
	Weak bool `json:"weak,omitempty"`
}

// Options controls a scan.
type Options struct {
	// Root is the directory to walk.
	Root string
	// IncludeVendor walks dependency directories too.
	IncludeVendor bool
	// Extra are additional patterns, each with one capture group holding the key.
	Extra []*regexp.Regexp
}

// keyPattern is what a key looks like inside a matched form. Anchoring to this
// alphabet is what makes env("STRIPE_{$mode}_SECRET") invisible rather than
// half-read.
const keyPattern = `([A-Z_][A-Z0-9_]*)`

// strongPatterns assert that a key ought to exist: the code will read it at
// runtime, so its absence from .env is a defect now.
//
// Each is anchored with a non-word lookalike guard on the left so envelope(...)
// and my_getenv(...) do not match: Go's regexp has no lookbehind, so the guard
// is a captured optional character the match simply includes.
var strongPatterns = []*regexp.Regexp{
	// PHP / Laravel: env('KEY'), env("KEY"), Env::get('KEY')
	regexp.MustCompile(`(?:^|[^\w])env\(\s*['"]` + keyPattern + `['"]`),
	regexp.MustCompile(`(?:^|[^\w])Env::get\(\s*['"]` + keyPattern + `['"]`),
	// Node and bundlers: process.env.KEY, process.env['KEY'], import.meta.env.KEY
	regexp.MustCompile(`process\.env\.` + keyPattern),
	regexp.MustCompile(`process\.env\[\s*['"]` + keyPattern + `['"]`),
	regexp.MustCompile(`import\.meta\.env\.` + keyPattern),
	// Go
	regexp.MustCompile(`(?:^|[^\w])os\.Getenv\(\s*"` + keyPattern + `"`),
	regexp.MustCompile(`(?:^|[^\w])os\.LookupEnv\(\s*"` + keyPattern + `"`),
	// Python
	regexp.MustCompile(`(?:^|[^\w])os\.environ\[\s*['"]` + keyPattern + `['"]`),
	regexp.MustCompile(`(?:^|[^\w])os\.environ\.get\(\s*['"]` + keyPattern + `['"]`),
	regexp.MustCompile(`(?:^|[^\w])getenv\(\s*['"]` + keyPattern + `['"]`),
}

// weakPatterns are interpolation forms. ${HOME} appears in every Dockerfile
// ever written, so these can confirm a key is used and can never declare one.
var weakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$\{` + keyPattern + `[}:]`),
	regexp.MustCompile(`\$` + keyPattern + `\b`),
}

// vendorDirs hold code the project did not write. Vendored code reads its own
// keys, not the project's, and reporting them buries every real finding.
// --include-vendor walks them anyway, for the rare project that keeps real code
// there.
var vendorDirs = map[string]bool{
	"vendor": true, "node_modules": true, "dist": true, "build": true,
	".next": true, "target": true, "__pycache__": true, ".venv": true, "venv": true,
}

// alwaysSkipDirs hold no source at all, and are skipped under every flag.
var alwaysSkipDirs = map[string]bool{
	".git": true, ".idea": true, ".vscode": true,
}

// skipFiles are the configuration files themselves. A key's own declaration is
// not a reference to it.
var skipFiles = map[string]bool{
	".env": true, ".env.example": true, ".env.schema": true, ".secrets": true,
}

// maxFileSize skips anything too large to be hand-written source.
const maxFileSize = 2 << 20

// Result is a completed walk. Skipped matters as much as References: a file
// warden could not read is a hole in the "unused" answer, since a key referenced
// only there looks dead.
type Result struct {
	References []Reference
	Skipped    []string
}

// Scan returns just the references, for callers that have no way to surface a
// coverage gap.
func Scan(opts Options) ([]Reference, error) {
	res, err := ScanTree(opts)
	return res.References, err
}

// ScanTree walks the tree and reports every environment reference it recognises,
// along with the files it could not read.
func ScanTree(opts Options) (Result, error) {
	var res Result
	root := opts.Root

	// Built once. Appending to the package-level slice per file would be both
	// wasted work and a chance to write into its backing array.
	patterns := make([]*regexp.Regexp, 0, len(strongPatterns)+len(opts.Extra))
	patterns = append(patterns, strongPatterns...)
	patterns = append(patterns, opts.Extra...)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory is not a reason to abandon the tree.
			return nil //nolint:nilerr
		}
		name := d.Name()
		if d.IsDir() {
			if path == root {
				return nil
			}
			if alwaysSkipDirs[name] || (vendorDirs[name] && !opts.IncludeVendor) {
				return fs.SkipDir
			}
			return nil
		}
		if skipFiles[name] || strings.HasPrefix(name, ".env.") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}

		info, err := d.Info()
		if err != nil || info.Size() > maxFileSize {
			res.Skipped = append(res.Skipped, rel)
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(body, 0) >= 0 { // binary
			res.Skipped = append(res.Skipped, rel)
			return nil
		}
		res.References = append(res.References, scanBody(string(body), rel, patterns)...)
		return nil
	})
	return res, err
}

// scanBody is the per-file half, kept separate so it can be tested without a
// filesystem and reused by any caller that already has the bytes.
//
// strong is the full strong-pattern set including any caller-supplied extras;
// the weak set is fixed.
func scanBody(body, path string, strong []*regexp.Regexp) []Reference {
	var out []Reference
	type place struct {
		key  string
		line int
	}
	seen := map[place]bool{} // one reference per key per line

	for i, line := range strings.Split(body, "\n") {
		record := func(key string, weak bool) {
			if key == "" || seen[place{key, i}] {
				return
			}
			seen[place{key, i}] = true
			out = append(out, Reference{Key: key, Path: path, Line: i + 1, Weak: weak})
		}
		for _, re := range strong {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				record(m[1], false)
			}
		}
		for _, re := range weakPatterns {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				record(m[1], true)
			}
		}
	}
	return out
}
