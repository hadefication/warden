package cli

import (
	"os"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
)

// TestMain makes the fake prompter the default for every test in this package.
//
// prompt.Default() on a developer's Mac is a real osascript dialog with a
// 60-second timeout. A test that exercises a write command without replacing the
// prompter does not fail — it hangs, waiting on a dialog nobody is looking at,
// and pops that dialog onto the screen of whoever ran `go test`. Defaulting to
// the fake means a test has to opt *in* to a real prompt, which nothing should.
func TestMain(m *testing.M) {
	SetPrompter = prompt.Fake{}

	// hook --check otherwise reports on whichever warden is installed on the
	// machine running the tests: the previous release on a developer's Mac, and
	// nothing at all on CI. Tests that care about those answers set them.
	LookWarden = func() (string, error) { return "/usr/local/bin/warden", nil }
	GuardProbe = func(string) error { return nil }

	os.Exit(m.Run())
}
