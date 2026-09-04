package classify

import (
	"strings"

	"github.com/webteractive/warden/internal/secret"
)

// RuleFailClosed is the rule reported when nothing matched a key and it was
// called secret only by the closing default.
//
// It is exported because "secret because a rule said so" and "secret because
// nothing said otherwise" are different facts, and a caller deciding whether a
// reclassification is routine or dangerous needs to tell them apart.
const RuleFailClosed = "default:fail-closed"

// FailClosed reports whether this result came from the closing default rather
// than from a rule, an allowlist, or an override.
func (r Result) FailClosed() bool { return r.Rule == RuleFailClosed }

// Classify decides a key's sensitivity. Precedence, first match wins:
//
//  1. the value's shape — a recognisable credential format. This is
//     unwaivable, and deliberately outranks the schema: an override is a way to
//     fix a heuristic miss, not a way to unmask a live API key.
//  2. an explicit entry for this project in ~/.warden/schema
//  3. a legacy .env.schema override
//  4. the public allowlist
//  5. secret name patterns
//  6. secret by default — fail closed
//
// Either schema may be nil when its source has no override for this project.
func Classify(key string, value secret.Secret, userSchema, projectSchema *Schema) Result {
	if rule, ok := ShapeRule(value); ok {
		return Result{Class: Secret, Rule: rule}
	}
	if userSchema != nil {
		if class, ok := userSchema.Lookup(key); ok {
			return Result{Class: class, Rule: "user-schema"}
		}
	}
	if projectSchema != nil {
		if class, ok := projectSchema.Lookup(key); ok {
			return Result{Class: class, Rule: "project-schema"}
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
	return Result{Class: Secret, Rule: RuleFailClosed}
}
