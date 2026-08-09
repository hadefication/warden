// Package prompt collects a secret value from the user through a channel the
// calling agent cannot observe.
//
// The typed value travels from the dialog into a secret.Secret and then to the
// file. It is never formatted into an error, logged, or echoed — including on
// the failure paths, where the temptation to quote the raw output back is
// strongest.
package prompt

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/webteractive/warden/internal/secret"
)

var (
	// ErrCancelled means the user dismissed the prompt or let it time out.
	ErrCancelled = errors.New("cancelled")
	// ErrUnavailable means there is no channel to ask the user through.
	ErrUnavailable = errors.New("no interactive prompt available")
)

// timeoutSentinel distinguishes a timeout from an empty answer. AppleScript
// returns "" for both, so the script emits this marker when it gives up.
const timeoutSentinel = "__WARDEN_TIMED_OUT__"

// Prompter asks the user for a value.
type Prompter interface {
	// AskSecret prompts for key, showing path so the user can see which file
	// they are authorising a write to.
	AskSecret(key, path string) (secret.Secret, error)
}

// Fake is a test double.
type Fake struct {
	Value string
	Err   error
}

func (f Fake) AskSecret(string, string) (secret.Secret, error) {
	if f.Err != nil {
		return "", f.Err
	}
	return secret.Secret(f.Value), nil
}

// Refusing is used when no interactive channel exists. It tells the user the
// exact command to run themselves.
type Refusing struct{}

func (Refusing) AskSecret(key, path string) (secret.Secret, error) {
	return "", fmt.Errorf(
		"%w — run this yourself in a terminal: warden set --secret %s (target: %s)",
		ErrUnavailable, key, path)
}

// Osascript shows a native macOS dialog with a hidden answer field.
type Osascript struct {
	Timeout time.Duration
}

func (o Osascript) AskSecret(key, path string) (secret.Secret, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	cmd := exec.Command("osascript", "-e", buildScript(key, path, int(timeout.Seconds())))
	out, err := cmd.Output()
	if err != nil {
		// A user pressing Cancel makes osascript exit non-zero. Report the
		// cancellation, never the command's output.
		return "", ErrCancelled
	}
	return parseOsascript(string(out))
}

// buildScript renders the AppleScript. The dialog names both the key and the
// target file so the user can see what they are authorising before typing.
func buildScript(key, path string, seconds int) string {
	msg := fmt.Sprintf("Enter the value for %s\n\nIt will be written to:\n%s", key, path)
	return fmt.Sprintf(
		"set r to display dialog %s with title %s default answer \"\" with hidden answer giving up after %d\n"+
			"if gave up of r then\n  return %s\nend if\n"+
			"return text returned of r",
		applescriptString(msg),
		applescriptString("warden — "+key),
		seconds,
		applescriptString(timeoutSentinel),
	)
}

func applescriptString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// parseOsascript converts dialog output into a Secret. It never includes the
// raw output in an error, because that output is the secret.
func parseOsascript(raw string) (secret.Secret, error) {
	v := strings.TrimSuffix(raw, "\n")
	if v == timeoutSentinel {
		return "", fmt.Errorf("dialog timed out: %w", ErrCancelled)
	}
	if v == "" {
		return "", fmt.Errorf("empty value: %w", ErrCancelled)
	}
	return secret.Secret(v), nil
}

// TTY reads from the controlling terminal with echo disabled.
type TTY struct{}

func (TTY) AskSecret(key, path string) (secret.Secret, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", ErrUnavailable
	}
	defer tty.Close()

	fmt.Fprintf(tty, "Value for %s (written to %s): ", key, path)
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", ErrCancelled
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty value: %w", ErrCancelled)
	}
	return secret.Secret(b), nil
}

// Default picks the best available channel: a native dialog on macOS, a TTY
// where one exists, and otherwise a refusal that tells the user what to run.
func Default() Prompter {
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("osascript"); err == nil {
			return Osascript{}
		}
	}
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		return TTY{}
	}
	return Refusing{}
}
