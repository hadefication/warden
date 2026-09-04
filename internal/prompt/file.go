package prompt

import (
	"fmt"
	"os"
	"strings"

	"github.com/webteractive/warden/internal/secret"
)

// File supplies the value from a file that warden opens itself.
//
// The caller hands over a path, never the value — which is what keeps this as
// strong a channel as the prompt. An agent that pipes a value has already
// handled it; an agent that names a file has not.
//
// The embedded Prompter carries authorisation (Confirm, ConfirmAction) through
// to the human. Only the value comes from the file.
type File struct {
	Prompter
	Path string
}

func (f File) AskSecret(string, string) (secret.Secret, error) {
	raw, err := os.ReadFile(f.Path)
	if err != nil {
		// os.ReadFile's error names the path and the reason, never the contents.
		return "", fmt.Errorf("reading value file: %w", err)
	}
	return fromRaw(string(raw))
}

// fromRaw applies the hygiene every non-interactive channel shares.
//
// It strips exactly one trailing newline, because that is the one a file or a
// pipeline adds and the user did not type. Stripping more would silently change
// a value that legitimately ends in blank space, and the caller cannot see what
// warden decided — so warden decides as little as possible.
//
// No error below may include raw: these errors are the one place a value would
// otherwise reach the caller.
func fromRaw(raw string) (secret.Secret, error) {
	v := strings.TrimSuffix(raw, "\n")
	v = strings.TrimSuffix(v, "\r")

	if v == "" {
		return "", fmt.Errorf("empty value: %w", ErrCancelled)
	}
	// Interior line breaks are kept. envfile escapes them onto a single stored
	// line, so a PEM block or a service-account JSON survives the round trip —
	// which is most of why reading from a file is worth having at all.
	return secret.Secret(v), nil
}
