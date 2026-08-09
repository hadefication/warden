// Package secret provides a string type that cannot be printed by accident.
//
// Every value that leaves internal/store is a Secret. Its Format method
// intercepts all fmt verbs and its MarshalJSON intercepts encoding/json, so a
// stray log line or JSON encode anywhere in the codebase emits "<redacted>"
// rather than a credential. The only way to obtain the underlying text is
// Expose, which is deliberately greppable: every call site is a reviewed
// decision about letting a value escape.
package secret

import "fmt"

// Redacted is what a Secret renders as in any output.
const Redacted = "<redacted>"

// Secret is a configuration value that must not be printed.
type Secret string

// Format implements fmt.Formatter for every verb, so %v, %s, %q, %#v and
// friends all render as Redacted. Defining Format (rather than only String)
// is what makes this airtight — String alone leaves %q and %#v leaking.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(Redacted))
}

// String implements fmt.Stringer for callers that invoke it directly.
func (s Secret) String() string { return Redacted }

// MarshalJSON renders the secret as a redacted JSON string.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + Redacted + `"`), nil
}

// Expose returns the underlying value. This is the single escape hatch;
// grep for it to audit every place a value can leave the safe zone.
func (s Secret) Expose() string { return string(s) }

// IsSet reports whether the value is present and non-empty. A declared-but-empty
// key (KEY=) is not "set" — an empty value is not usable configuration.
func (s Secret) IsSet() bool { return len(s) > 0 }
