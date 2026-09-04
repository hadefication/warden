package main

import (
	"os"

	"github.com/webteractive/warden/internal/cli"
)

func main() {
	if piped := pipedStdin(); piped != nil {
		cli.SetStdin = piped
	}
	// cli.Run writes any error message to stderr itself, so that error message
	// is covered by the canary leak test rather than escaping through main.
	os.Exit(cli.ExitCode(cli.Run(os.Args[1:], os.Stdout, os.Stderr)))
}

// pipedStdin returns os.Stdin when a value was genuinely piped or redirected
// into warden, and nil otherwise.
//
// It matches only a named pipe — `cmd | warden` — rather than asking whether
// stdin is a terminal. The negative test is wrong here: /dev/null, a closed
// descriptor, and a launchd job's stdin are all "not a terminal" while carrying
// no value at all, and treating them as a value source would replace the macOS
// dialog with an instant "empty value" for anyone running warden from a script
// or a GUI context.
//
// A regular file is deliberately not matched either, even though `warden < f`
// looks like a deliberate hand-off. A script invoked as `./deploy.sh < input`
// gives every command it runs a regular-file stdin, so warden would silently
// swallow input meant for the script and store it as the credential — with no
// prompt, and nothing on screen to say the value came from the wrong place.
// The explicit spelling is --from-file, which cannot be triggered by accident.
func pipedStdin() *os.File {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	if carriesAValue(fi.Mode()) {
		return os.Stdin
	}
	return nil
}

// carriesAValue reports whether a stdin of this mode was written by a caller
// handing warden a value. Split out from pipedStdin so the decision can be
// tested against each mode directly — a test binary's own stdin is whatever the
// harness gives it, which is exactly the ambiguity this function exists to
// resolve.
func carriesAValue(mode os.FileMode) bool {
	return mode&os.ModeNamedPipe != 0
}
