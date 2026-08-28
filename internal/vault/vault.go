package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/webteractive/warden/internal/keyring"
	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/secret"
)

var (
	// ErrNoVault means there is no vault, or no such entry in it.
	ErrNoVault = errors.New("no such vault entry")
	// ErrExists means init was asked to create a vault that already exists.
	ErrExists = errors.New("a vault already exists")
	// ErrLocked means another warden process is writing.
	ErrLocked = errors.New("the vault is being written by another process")
	// ErrNoMasterKey means the file exists but its key does not. This is
	// unrecoverable, and warden must never respond by generating a new one.
	ErrNoMasterKey = errors.New("the vault's master key is missing")
)

// lockStaleAfter is how long a lockfile may exist before it is assumed to
// belong to a process that died.
const lockStaleAfter = 30 * time.Second

// argon2id parameters. Deliberately modest: this runs on every command in
// passphrase mode, and the passphrase path already carries a dialog.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// Options configures a vault. Keyring, Prompt and Now are injected so tests
// never touch a real keyring, a real dialog, or a real clock.
type Options struct {
	Home    string
	Keyring keyring.Keyring
	Prompt  prompt.Prompter
	Now     func() time.Time
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

func (o Options) kr() keyring.Keyring {
	if o.Keyring == nil {
		return keyring.Default()
	}
	return o.Keyring
}

// Path is the vault file for a home directory.
func Path(home string) string { return filepath.Join(home, ".warden", "vault") }

// V is an open vault.
type V struct {
	opts     Options
	path     string
	hdr      header
	key      []byte
	entries  []Entry
	exists   bool
	loosened bool
}

// Init creates an empty vault in the given mode, refusing to overwrite one.
//
// Bare `vault set` reaches Save without an Init, which creates a keyring-mode
// vault implicitly. Init exists for the other direction: choosing argon2id on a
// machine that does have a keyring.
func Init(o Options, mode Mode) error {
	path := Path(o.Home)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w at %s", ErrExists, path)
	}
	// Save establishes the key under the lock; doing it here as well would
	// reopen the race that ordering closes.
	v := &V{opts: o, path: path, hdr: header{Mode: mode}}
	return v.Save()
}

// Open reads and unseals the vault. A missing file is not an error: reads treat
// it as empty, and only Save creates one.
func Open(o Options) (*V, error) {
	path := Path(o.Home)
	v := &V{opts: o, path: path, hdr: header{Mode: ModeKeyring}}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	v.exists = true

	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		v.loosened = true
	}

	line, body, ok := strings.Cut(string(raw), "\n")
	if !ok {
		return nil, fmt.Errorf("%w: the file has no body", ErrBadFormat)
	}
	if v.hdr, err = parseHeader(line); err != nil {
		return nil, err
	}

	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return nil, fmt.Errorf("%w: the body is not valid base64", ErrBadFormat)
	}
	if err := v.resolveKey(); err != nil {
		return nil, err
	}
	if v.entries, err = openDoc(v.key, blob); err != nil {
		return nil, err
	}
	return v, nil
}

// Path is the backing file, safe to show a user.
func (v *V) Path() string { return v.path }

// Mode is how this vault's key is derived.
func (v *V) Mode() Mode { return v.hdr.Mode }

// Exists reports whether the file was there when this vault was opened.
func (v *V) Exists() bool { return v.exists }

// Loosened reports that the file was found more permissive than 0600. Save
// corrects it; the caller decides whether to mention it.
func (v *V) Loosened() bool { return v.loosened }

// List returns every unexpired entry, sorted by name.
func (v *V) List() []Entry {
	now := v.opts.now()
	out := make([]Entry, 0, len(v.entries))
	for _, e := range v.entries {
		if !e.ExpiredAt(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get resolves a name. An expired entry is reported as absent, which is what
// makes expiry indistinguishable from never having existed.
func (v *V) Get(name string) (Entry, bool) {
	now := v.opts.now()
	for _, e := range v.entries {
		if e.Name == name && !e.ExpiredAt(now) {
			return e, true
		}
	}
	return Entry{}, false
}

// Put adds or replaces an entry by name, stamping Created from the clock.
func (v *V) Put(e Entry) error {
	if err := ValidateName(e.Name); err != nil {
		return err
	}
	if err := ValidateKey(e.Key); err != nil {
		return err
	}
	now := v.opts.now()
	if !e.Permanent() {
		if err := ValidateTTL(e.Expires.Sub(now)); err != nil {
			return err
		}
	}
	if e.Created.IsZero() {
		e.Created = now
	}

	for i := range v.entries {
		if v.entries[i].Name == e.Name {
			v.entries[i] = e
			return nil
		}
	}
	v.entries = append(v.entries, e)
	return nil
}

// Remove drops an entry, reporting whether it was there.
func (v *V) Remove(name string) bool {
	for i := range v.entries {
		if v.entries[i].Name == name {
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			return true
		}
	}
	return false
}

// Rename moves an entry to a new name.
func (v *V) Rename(old, next string) error {
	if err := ValidateName(next); err != nil {
		return err
	}
	if _, ok := v.Get(old); !ok {
		return fmt.Errorf("%q: %w", old, ErrNoVault)
	}
	if _, taken := v.Get(next); taken && next != old {
		return fmt.Errorf("%q: %w", next, ErrExists)
	}
	for i := range v.entries {
		if v.entries[i].Name == old {
			v.entries[i].Name = next
			return nil
		}
	}
	return fmt.Errorf("%q: %w", old, ErrNoVault)
}

// Save purges expired entries, reseals the whole file, and lands it atomically.
//
// The whole document reseals on every write, so two processes writing at once
// would have the second silently drop the first's entry. The lockfile is what
// stops that.
func (v *V) Save() error {
	return withLock(v.path, func() error {
		// Establishing the key belongs inside the lock, not before it. Minting
		// it outside means a writer that then loses the lock has already
		// replaced the keychain item, leaving a displaced key beside a file
		// sealed with the old one — the unrecoverable state this package exists
		// to avoid.
		if err := v.establishKey(); err != nil {
			return err
		}

		now := v.opts.now()
		kept := make([]Entry, 0, len(v.entries))
		for _, e := range v.entries {
			if !e.ExpiredAt(now) {
				kept = append(kept, e)
			}
		}
		v.entries = kept

		blob, err := sealDoc(v.key, v.entries)
		if err != nil {
			return err
		}
		body := renderHeader(v.hdr) + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n"

		if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Dir(v.path), err)
		}
		tmp := v.path + ".tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
			return fmt.Errorf("writing the vault: %w", err)
		}
		if err := os.Rename(tmp, v.path); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replacing the vault: %w", err)
		}
		// A pre-existing file keeps its own mode through a rename on some
		// systems, so assert it rather than trusting WriteFile's.
		if err := os.Chmod(v.path, 0o600); err != nil {
			return fmt.Errorf("setting permissions: %w", err)
		}
		v.exists, v.loosened = true, false
		return nil
	})
}

// establishKey obtains the key for a write, creating one on first use.
func (v *V) establishKey() error {
	if len(v.key) == keyLen {
		return nil
	}
	if v.hdr.Mode == ModeArgon2id {
		return v.deriveFromPassphrase()
	}

	kr := v.opts.kr()
	mk, err := kr.Get()
	switch {
	case err == nil:
		return v.decodeMasterKey(mk)
	case errors.Is(err, keyring.ErrNotFound) && !v.exists:
		// First use: mint a key and store it.
		key := make([]byte, keyLen)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("generating a master key: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(key)
		if err := kr.Set(secret.Secret(encoded)); err != nil {
			return err
		}
		v.key = key
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return v.noMasterKey()
	case errors.Is(err, keyring.ErrUnavailable):
		return fmt.Errorf(
			"%w: this machine offers no keyring — create a passphrase vault instead with "+
				"`warden vault init --passphrase`", err)
	default:
		return err
	}
}

// resolveKey obtains the key for a read of an existing file.
func (v *V) resolveKey() error {
	if v.hdr.Mode == ModeArgon2id {
		return v.deriveFromPassphrase()
	}
	mk, err := v.opts.kr().Get()
	switch {
	case err == nil:
		return v.decodeMasterKey(mk)
	case errors.Is(err, keyring.ErrNotFound):
		return v.noMasterKey()
	case errors.Is(err, keyring.ErrUnavailable):
		return fmt.Errorf(
			"%w: this vault was sealed with a keyring key and this machine has no keyring", ErrNoMasterKey)
	default:
		return err
	}
}

// noMasterKey is the unrecoverable case: the file is here and its key is not.
//
// Generating a fresh key and resealing would present total data loss as
// success, so warden refuses and names both real options instead.
func (v *V) noMasterKey() error {
	return fmt.Errorf(
		"%w — %s was sealed with a key that is no longer in this machine's keychain. "+
			"Warden will not create a new one, because that would silently discard every entry. "+
			"Either restore the keychain item (service %q, account %q), or delete %s and start over",
		ErrNoMasterKey, v.path, "warden", "vault-master", v.path)
}

func (v *V) decodeMasterKey(mk secret.Secret) error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(mk.Expose()))
	if err != nil {
		return fmt.Errorf("%w: the stored master key is not valid base64", ErrNoMasterKey)
	}
	if len(key) != keyLen {
		return fmt.Errorf("%w: the stored master key is %d bytes, want %d", ErrNoMasterKey, len(key), keyLen)
	}
	v.key = key
	return nil
}

// deriveFromPassphrase collects the passphrase through the prompt — the same
// channel set --secret uses, so it never passes through a calling agent.
func (v *V) deriveFromPassphrase() error {
	if len(v.hdr.Salt) == 0 {
		salt := make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generating a salt: %w", err)
		}
		v.hdr.Salt = salt
	}
	p := v.opts.Prompt
	if p == nil {
		p = prompt.Default()
	}
	pass, err := p.AskSecret("vault passphrase", v.path)
	if err != nil {
		return err
	}
	v.key = argon2.IDKey([]byte(pass.Expose()), v.hdr.Salt, argonTime, argonMemory, argonThreads, keyLen)
	return nil
}

// withLock serialises writers through an O_EXCL lockfile, breaking one left
// behind by a process that died.
func withLock(path string, fn func() error) error {
	lock := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(lock), err)
	}

	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		fi, statErr := os.Stat(lock)
		if statErr != nil || time.Since(fi.ModTime()) < lockStaleAfter {
			return fmt.Errorf("%w (lock: %s)", ErrLocked, lock)
		}
		// Stale: the holder is gone. Break it and take it once.
		_ = os.Remove(lock)
		if f, err = os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
			return fmt.Errorf("%w (lock: %s)", ErrLocked, lock)
		}
	} else if err != nil {
		return fmt.Errorf("taking the vault lock: %w", err)
	}
	_ = f.Close()
	defer func() { _ = os.Remove(lock) }()

	return fn()
}
