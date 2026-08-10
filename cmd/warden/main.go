package main

import (
	"os"

	"github.com/hadefication/warden/internal/cli"
)

func main() {
	// cli.Run writes any error message to stderr itself, so that error output
	// is covered by the canary leak test rather than escaping through main.
	os.Exit(cli.ExitCode(cli.Run(os.Args[1:], os.Stdout, os.Stderr)))
}
