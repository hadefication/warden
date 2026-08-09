package main

import (
	"fmt"
	"os"

	"github.com/webteractive/warden/internal/cli"
)

func main() {
	err := cli.Run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
	}
	os.Exit(cli.ExitCode(err))
}
