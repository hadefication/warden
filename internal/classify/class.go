// Package classify decides whether a configuration key holds something
// sensitive. It answers with a class and a reason, and never with a value.
package classify

// Class is a key's sensitivity.
type Class int

const (
	// Public keys may be read and written freely by an agent.
	Public Class = iota
	// Secret keys may never be printed, and may only be written through a
	// prompt the agent cannot observe.
	Secret
)

func (c Class) String() string {
	if c == Public {
		return "public"
	}
	return "secret"
}

// Result is a classification decision plus the rule that produced it, so a
// surprising answer is diagnosable rather than mysterious.
type Result struct {
	Class Class
	Rule  string
}
