package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "warden: not yet wired up")
	os.Exit(3)
}
