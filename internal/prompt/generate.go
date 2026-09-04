package prompt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/webteractive/warden/internal/secret"
)

// MinGeneratedBytes is the shortest secret warden will mint. Below this the
// flag stops being a convenience and starts being a way to create a weak
// credential without noticing.
const MinGeneratedBytes = 16

// DefaultGeneratedBytes is the length used when none is given.
const DefaultGeneratedBytes = 32

// ErrTooShort means the requested length was below MinGeneratedBytes.
var ErrTooShort = fmt.Errorf("generated secrets must be at least %d bytes", MinGeneratedBytes)

// Generated mints a value from crypto/rand instead of asking anyone for one.
//
// This is the only channel where nobody — not the user, not a calling agent —
// ever holds the value. That makes it the right answer for a credential that
// has already leaked: the caller cannot know the replacement it just installed.
//
// The output is lowercase hex so it needs no .env quoting and survives being
// copied through shells and web forms unchanged.
type Generated struct {
	Prompter
	Bytes int
}

func (g Generated) AskSecret(string, string) (secret.Secret, error) {
	n := g.Bytes
	if n == 0 {
		n = DefaultGeneratedBytes
	}
	if n < MinGeneratedBytes {
		return "", ErrTooShort
	}

	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// Wrap without the buffer: a partially filled buffer is still key material.
		return "", errors.New("generating a value: the system random source failed")
	}
	return secret.Secret(hex.EncodeToString(buf)), nil
}
