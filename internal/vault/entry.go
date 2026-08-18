// Package vault stores credentials warden owns, rather than credentials a
// project's .env happens to hold.
//
// Every value leaves this package as a secret.Secret. internal/cli,
// internal/mcpserver and cmd/warden are forbidden from importing it —
// internal/cli/arch_test.go enforces that — so a surface reaches the vault only
// through internal/query and internal/write, exactly as it reaches a .env.
package vault

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/hadefication/warden/internal/secret"
)

// MaxTTL caps a temporary entry at 30 days.
//
// The cap's job is to stop --ttl 8760h being used as a permanent entry that
// quietly dies. An entry with no TTL is unbounded, and that asymmetry is the
// point: absent means "this lives here until I remove it", stated plainly. A
// large number pretending to mean the same thing is the failure mode.
const MaxTTL = 30 * 24 * time.Hour

// Mode is how the file's master key is derived.
type Mode string

const (
	// ModeKeyring takes the key from the OS keyring. The default.
	ModeKeyring Mode = "keyring"
	// ModeArgon2id derives it from a passphrase.
	ModeArgon2id Mode = "argon2id"
)

var (
	// ErrBadName means an entry name is not a legal name.
	ErrBadName = errors.New("invalid entry name")
	// ErrBadKey means a target env key is not a legal env key.
	ErrBadKey = errors.New("invalid env key")
	// ErrTTLTooLong means a requested window exceeds MaxTTL.
	ErrTTLTooLong = errors.New("ttl exceeds the maximum")
	// ErrBadFormat means the file is not a vault this build understands.
	ErrBadFormat = errors.New("not a readable warden vault")
	// ErrUndecryptable means the blob failed authentication: tampering, or the
	// wrong key. Warden never half-parses a vault.
	ErrUndecryptable = errors.New("vault could not be decrypted")
)

// Entry is one stored credential.
//
// Name is how it is addressed; Key is the env key it lands as. The indirection
// is what lets two projects with different DB_PASSWORD values coexist, which a
// store addressed by env key cannot do.
type Entry struct {
	Name    string
	Key     string
	Value   secret.Secret
	Created time.Time
	// Expires is the absolute deadline. The zero time means permanent.
	Expires time.Time
}

// Permanent reports whether the entry has no deadline.
func (e Entry) Permanent() bool { return e.Expires.IsZero() }

// ExpiredAt reports whether the entry is past its deadline at now. The boundary
// belongs to the past: at exactly the deadline, the entry is gone.
func (e Entry) ExpiredAt(now time.Time) bool {
	return !e.Permanent() && !now.Before(e.Expires)
}

// A name is dot, dash, underscore and alphanumeric segments joined by slashes.
// Names are keys in a JSON document rather than paths on disk, but a name
// carrying a newline would corrupt list output, so the charset is validated on
// the way in.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// envKeyRE is the shape of an environment variable name.
var envKeyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// dayRE matches a whole number of days, which time.ParseDuration does not
// support and which is the unit a 30-day cap invites people to type.
var dayRE = regexp.MustCompile(`^(\d+)d$`)

// ValidateName accepts a legal entry name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf(
			"%q: %w — use letters, digits, dot, dash and underscore, in segments joined by /",
			name, ErrBadName)
	}
	// "." and ".." are legal under the charset but read as path traversal to
	// every human who sees them, and a name is not a path. Refuse both.
	for _, seg := range splitSegments(name) {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%q: %w — %q is not a usable segment", name, ErrBadName, seg)
		}
	}
	return nil
}

// ValidateKey accepts a legal environment variable name.
func ValidateKey(key string) error {
	if !envKeyRE.MatchString(key) {
		return fmt.Errorf("%q: %w — env keys are upper case, digits and underscore", key, ErrBadKey)
	}
	return nil
}

// LooksLikeEnvKey reports whether a name may double as its own env key, which is
// what lets `warden vault set STRIPE_SECRET` omit --key.
func LooksLikeEnvKey(name string) bool { return envKeyRE.MatchString(name) }

// ValidateTTL accepts zero (permanent) or a window inside MaxTTL.
//
// It refuses rather than clamps. Silently shortening a requested window is the
// worst option available: the user would believe a credential lives for a year
// while it dies in a month, which is precisely the surprise the cap exists to
// prevent.
func ValidateTTL(d time.Duration) error {
	if d == 0 {
		return nil
	}
	if d < 0 {
		return fmt.Errorf("%w: a negative window is not a deadline", ErrTTLTooLong)
	}
	if d > MaxTTL {
		return fmt.Errorf(
			"%w: %s is longer than the 30d maximum — either drop --ttl for a permanent entry, "+
				"or choose a window inside the cap",
			ErrTTLTooLong, d)
	}
	return nil
}

// ParseTTL accepts a Go duration, plus Nd for days.
//
// It lives here rather than in a surface package because both the CLI and the
// MCP server parse the same flag, and two copies of a duration parser drift.
func ParseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if m := dayRE.FindStringSubmatch(s); m != nil {
		days, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration — try 30m, 8h or 7d", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q is not a future window", s)
	}
	return d, nil
}

func splitSegments(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return append(out, name[start:])
}
