package query

import (
	"time"

	"github.com/webteractive/warden/internal/keyring"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/vault"
)

// VaultKeyring and VaultNow are test seams, following the cli.SetPrompter
// precedent. Nil means the production default. Nothing but a test should assign
// them: internal/cli may not import internal/keyring at all, so this is how a
// test drives the vault surface without a real keychain.
var (
	VaultKeyring keyring.Keyring
	VaultNow     func() time.Time
)

// The three things a surface package needs from the vault layer, re-exported so
// it can ask without importing internal/vault — which arch_test.go forbids.

// LooksLikeEnvKey reports whether a name may double as its own env key.
func LooksLikeEnvKey(name string) bool { return vault.LooksLikeEnvKey(name) }

// ParseTTL parses a --ttl value: a Go duration, or Nd for days.
func ParseTTL(s string) (time.Duration, error) { return vault.ParseTTL(s) }

// ErrNoVaultEntry is vault.ErrNoVault, re-exported so a surface can match on it.
var ErrNoVaultEntry = vault.ErrNoVault

// Now is the clock the vault surfaces read, honouring the VaultNow seam. It
// exists so callers stop repeating the nil check — and, more to the point, so
// none of them quietly forgets it and starts reporting real time in a test.
func Now() time.Time {
	if VaultNow != nil {
		return VaultNow()
	}
	return time.Now()
}

// VaultRow is one entry's public-facing summary. It deliberately has no value
// field — the same rule Row follows for .env.
type VaultRow struct {
	Name      string
	Key       string
	Created   time.Time
	Expires   time.Time
	Permanent bool
}

// VQ is an open, read-only view of the vault.
type VQ struct{ v *vault.V }

// OpenVault reads the vault under home. A missing vault is not an error: it
// reads as empty, exactly as a missing entry does.
//
// p collects the passphrase for a vault in argon2id mode. A keyring-mode vault
// never reaches it.
func OpenVault(home string, p prompt.Prompter) (*VQ, error) {
	v, err := vault.Open(VaultOptions(home, p))
	if err != nil {
		return nil, err
	}
	return &VQ{v: v}, nil
}

// VaultOptions builds the options both surfaces open a vault with.
//
// It is exported so internal/write uses this one rather than keeping a copy:
// the seams below are what every vault test drives, and two constructors that
// must be updated in lockstep is exactly how a seam goes quietly dead in one of
// them.
func VaultOptions(home string, p prompt.Prompter) vault.Options {
	return vault.Options{
		Home:    home,
		Keyring: VaultKeyring,
		Prompt:  p,
		Now:     VaultNow,
	}
}

// Path is the backing file, safe to show a user.
func (q *VQ) Path() string { return q.v.Path() }

// Exists reports whether a vault file is there at all.
func (q *VQ) Exists() bool { return q.v.Exists() }

// Loosened reports that the vault was found more permissive than 0600.
func (q *VQ) Loosened() bool { return q.v.Loosened() }

// Mode names how the vault's key is derived: "keyring" or "argon2id".
func (q *VQ) Mode() string { return string(q.v.Mode()) }

// List summarises every unexpired entry, in name order.
func (q *VQ) List() []VaultRow {
	entries := q.v.List()
	rows := make([]VaultRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, VaultRow{
			Name:      e.Name,
			Key:       e.Key,
			Created:   e.Created,
			Expires:   e.Expires,
			Permanent: e.Permanent(),
		})
	}
	return rows
}

// Has reports whether a live entry exists under name. An expired entry is
// absent, which is what makes expiry indistinguishable from never having been.
func (q *VQ) Has(name string) bool {
	_, ok := q.v.Get(name)
	return ok
}
