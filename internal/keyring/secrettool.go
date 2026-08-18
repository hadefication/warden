package keyring

import (
	"github.com/hadefication/warden/internal/secret"
)

// SecretTool is the Linux backend, over libsecret's secret-tool.
type SecretTool struct{ Run Runner }

// Get reads the item. secret-tool lookup prints the secret with no trailing
// newline, and prints nothing at all when there is no match.
func (s SecretTool) Get() (secret.Secret, error) {
	out, err := s.Run("secret-tool", "", "lookup", "service", service, "account", account)
	if err != nil || len(out) == 0 {
		return "", ErrNotFound
	}
	return secret.Secret(out), nil
}

// Set writes the item. secret-tool store reads the secret from stdin exactly
// once — unlike security, it does not ask for a retype.
func (s SecretTool) Set(v secret.Secret) error {
	if _, err := s.Run("secret-tool", v.Expose(),
		"store", "--label="+service, "service", service, "account", account); err != nil {
		return wrapErr("write", err)
	}
	return nil
}

// Delete removes the item. An absent item is not an error.
func (s SecretTool) Delete() error {
	_, _ = s.Run("secret-tool", "", "clear", "service", service, "account", account)
	return nil
}
