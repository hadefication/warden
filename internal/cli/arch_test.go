package cli

import (
	"os/exec"
	"strings"
	"testing"
)

// The safety property depends on internal/query being the only way out of
// internal/store. If a surface package imports store directly, it can reach a
// raw value without a classification and every other guarantee here is void.
// This test makes that structural rather than customary.
func TestSurfacePackagesDoNotImportStoreDirectly(t *testing.T) {
	const forbidden = "github.com/hadefication/warden/internal/store"

	for _, pkg := range []string{
		"github.com/hadefication/warden/internal/cli",
		"github.com/hadefication/warden/internal/mcpserver",
		"github.com/hadefication/warden/cmd/warden",
	} {
		out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if imp == forbidden {
				t.Errorf("%s imports %s directly — it must go through internal/query or internal/write",
					pkg, forbidden)
			}
		}
	}
}

// Expose is the single documented escape hatch. Keeping its call sites few and
// deliberate is what makes them reviewable; this test surfaces new ones.
func TestExposeCallSitesStayFew(t *testing.T) {
	out, err := exec.Command("grep", "-rn", "--include=*.go", ".Expose()", "../..").Output()
	if err != nil && len(out) == 0 {
		t.Skip("grep unavailable")
	}
	var production []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" || strings.Contains(line, "_test.go") {
			continue
		}
		production = append(production, line)
	}
	// classify (shape check), query.Get, write.SetPublic, write.SetSecret.
	const budget = 6
	if len(production) > budget {
		t.Errorf("Expose() is called in %d production sites, budget is %d.\n"+
			"Each one lets a value escape the safe zone — review these and raise the budget "+
			"deliberately if the new call site is justified:\n%s",
			len(production), budget, strings.Join(production, "\n"))
	}
}

// internal/refs deals in key names and file paths. Keeping it structurally
// unable to hold a value is what makes it the cheapest analysis here to trust:
// the worst a bug in it can do is name the wrong file.
func TestRefsPackageCannotReachAValue(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Deps \"\\n\"}}",
		"github.com/hadefication/warden/internal/refs").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch dep {
		case "github.com/hadefication/warden/internal/store",
			"github.com/hadefication/warden/internal/secret",
			"github.com/hadefication/warden/internal/query":
			t.Errorf("internal/refs depends on %s — it must never be able to hold a value", dep)
		}
	}
}
