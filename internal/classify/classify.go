package classify

import (
	"strings"

	"github.com/webteractive/warden/internal/secret"
)

// Classify decides a key's sensitivity. Precedence, first match wins:
//
//  1. the value's shape — a recognisable credential format. This is
//     unwaivable, and deliberately outranks the schema: an override is a way to
//     fix a heuristic miss, not a way to unmask a live API key.
//  2. an explicit .env.schema override
//  3. the public allowlist
//  4. secret name patterns
//  5. secret by default — fail closed
//
// sch may be nil when the project has no override file.
func Classify(key string, value secret.Secret, sch *Schema) Result {
	if rule, ok := matchShape(value.Expose()); ok {
		return Result{Class: Secret, Rule: rule}
	}
	if sch != nil {
		if class, ok := sch.Lookup(key); ok {
			return Result{Class: class, Rule: "schema"}
		}
	}
	if strings.HasPrefix(key, "VITE_") {
		// Vite inlines these into browser bundles — public by deployment.
		return Result{Class: Public, Rule: "allowlist:VITE_*"}
	}
	if publicKeys[key] {
		return Result{Class: Public, Rule: "allowlist"}
	}
	if rule, ok := matchName(key); ok {
		return Result{Class: Secret, Rule: rule}
	}
	return Result{Class: Secret, Rule: "default:fail-closed"}
}

// Schema holds per-key overrides loaded from a project's .env.schema.
// Task 6 gives it a loader; until then only the nil case is exercised.
type Schema struct {
	entries map[string]Class
}

// Lookup returns an explicit override for key, if the schema declares one.
func (s *Schema) Lookup(key string) (Class, bool) {
	if s == nil {
		return Public, false
	}
	c, ok := s.entries[key]
	return c, ok
}
