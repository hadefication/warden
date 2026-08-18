package keyring

import (
	"strings"

	"github.com/hadefication/warden/internal/secret"
)

// Security is the macOS backend, over /usr/bin/security.
type Security struct{ Run Runner }

// Get reads the item. -w prints only the password, with a trailing newline.
func (s Security) Get() (secret.Secret, error) {
	out, err := s.Run("security", "",
		"find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		// security exits non-zero for "item not found" and for a locked
		// keychain alike. Both mean the same thing to a caller: no key here.
		return "", ErrNotFound
	}
	return secret.Secret(strings.TrimRight(string(out), "\r\n")), nil
}

// Set writes the item, replacing any existing one.
//
// -w is passed last and with no value, which makes security read the password
// from stdin rather than argv. It asks twice — once to enter and once to retype
// — so the value is piped twice. A single line leaves the retype reading EOF,
// which security reports as "passwords don't match" and then creates the item
// with an empty password: a silent, total data loss.
func (s Security) Set(v secret.Secret) error {
	stdin := v.Expose() + "\n" + v.Expose() + "\n"
	if _, err := s.Run("security", stdin,
		"add-generic-password", "-s", service, "-a", account, "-U", "-w"); err != nil {
		return wrapErr("write", err)
	}
	return nil
}

// Delete removes the item. An absent item is not an error.
func (s Security) Delete() error {
	_, _ = s.Run("security", "", "delete-generic-password", "-s", service, "-a", account)
	return nil
}
