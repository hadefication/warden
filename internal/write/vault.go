package write

import (
	"errors"
	"fmt"
	"time"

	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
	"github.com/webteractive/warden/internal/vault"
)

// ErrDestinationSet means the destination already holds a value for the key, and
// the push was not forced.
var ErrDestinationSet = errors.New("the destination key is already set")

// EditOpts are the metadata changes Edit applies. A zero field leaves that
// property alone; TTL is a pointer so that clearing a deadline (a pointer to 0)
// is distinguishable from not touching it (nil).
type EditOpts struct {
	NewName string
	NewKey  string
	TTL     *time.Duration
}

// VW is an open, writable view of the vault.
type VW struct {
	v    *vault.V
	p    prompt.Prompter
	home string
}

// InitVault creates an empty vault, choosing how its key is derived.
//
// Bare `vault set` creates a keyring vault implicitly, so this exists for the
// other direction: opting into a passphrase on a machine that has a keyring.
func InitVault(home string, p prompt.Prompter, passphrase bool) error {
	mode := vault.ModeKeyring
	if passphrase {
		mode = vault.ModeArgon2id
	}
	return vault.Init(query.VaultOptions(home, p), mode)
}

// OpenVault opens the vault under home for writing.
func OpenVault(home string, p prompt.Prompter) (*VW, error) {
	v, err := vault.Open(query.VaultOptions(home, p))
	if err != nil {
		return nil, err
	}
	return &VW{v: v, p: p, home: home}, nil
}

// Path is the vault file.
func (w *VW) Path() string { return w.v.Path() }

// Set stores a value typed at the prompt under name, targeting key.
//
// Replacing a live entry asks first: what is at stake is a value the user may
// not be able to recover, which is destruction rather than disclosure, so it
// takes the plain ceremony and never the retype.
func (w *VW) Set(name, key string, ttl time.Duration) error {
	if err := vault.ValidateName(name); err != nil {
		return err
	}
	if err := vault.ValidateKey(key); err != nil {
		return err
	}
	if err := vault.ValidateTTL(ttl); err != nil {
		return err
	}

	if _, exists := w.v.Get(name); exists {
		if err := w.p.ConfirmAction("replace", name, w.v.Path()); err != nil {
			return err
		}
	}

	value, err := w.p.AskSecret(name, w.v.Path())
	if err != nil {
		return err
	}

	e := vault.Entry{Name: name, Key: key, Value: value}
	if ttl > 0 {
		e.Expires = query.Now().Add(ttl)
	}
	if err := w.v.Put(e); err != nil {
		return err
	}
	return w.v.Save()
}

// Edit changes an entry's metadata. It never touches the value, so there is
// nothing to disclose — but renaming and retargeting can strand a project, and
// shortening a window can strand a session, so it confirms.
func (w *VW) Edit(name string, o EditOpts) error {
	e, ok := w.v.Get(name)
	if !ok {
		return fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}
	if o.NewKey != "" {
		if err := vault.ValidateKey(o.NewKey); err != nil {
			return err
		}
	}
	if o.NewName != "" {
		if err := vault.ValidateName(o.NewName); err != nil {
			return err
		}
	}
	if o.TTL != nil {
		if err := vault.ValidateTTL(*o.TTL); err != nil {
			return err
		}
	}
	if err := w.p.ConfirmAction("edit", name, w.v.Path()); err != nil {
		return err
	}

	if o.NewKey != "" {
		e.Key = o.NewKey
	}
	if o.TTL != nil {
		if *o.TTL == 0 {
			e.Expires = time.Time{}
		} else {
			e.Expires = query.Now().Add(*o.TTL)
		}
	}
	// Put replaces by name, so a rename is a remove plus a put under the new one.
	if o.NewName != "" && o.NewName != name {
		w.v.Remove(name)
		e.Name = o.NewName
	}
	if err := w.v.Put(e); err != nil {
		return err
	}
	return w.v.Save()
}

// Remove deletes an entry once the user authorises it. An absent entry is
// refused without asking: there is nothing to lose, and asking anyway would
// train the answer.
func (w *VW) Remove(name string) error {
	if _, ok := w.v.Get(name); !ok {
		return fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}
	if err := w.p.ConfirmAction("remove", name, w.v.Path()); err != nil {
		return err
	}
	w.v.Remove(name)
	return w.v.Save()
}

// PushResult reports where a value landed, with no value and no length.
type PushResult struct {
	Key  string
	Path string
}

// Push copies an entry's value into a destination store.
//
// This is the operation that moves a credential from a file that exists nowhere
// else into one that may well be committed, so it confirms by default. yes
// skips that and is reachable only from the CLI — the MCP surface never sets it.
//
// The value crosses inside a secret.Secret and is exposed once, in
// setFromVault. It is never formatted, never logged, and never in argv.
func (w *VW) Push(name string, dest query.Scope, as string, force, yes bool) (PushResult, error) {
	e, ok := w.v.Get(name)
	if !ok {
		return PushResult{}, fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}

	key := e.Key
	if as != "" {
		if err := vault.ValidateKey(as); err != nil {
			return PushResult{}, err
		}
		key = as
	}

	dw, err := Open(dest, w.p)
	if err != nil {
		return PushResult{}, err
	}
	if dw.has(key) && !force {
		return PushResult{}, fmt.Errorf(
			"%s in %s: %w — pass --force to overwrite it", key, dw.Path(), ErrDestinationSet)
	}
	if !yes {
		if err := w.p.ConfirmAction("push", key, dw.Path()); err != nil {
			return PushResult{}, err
		}
	}
	if err := dw.setFromVault(key, e.Value); err != nil {
		return PushResult{}, err
	}
	return PushResult{Key: key, Path: dw.Path()}, nil
}
