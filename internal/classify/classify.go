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
	return Result{Class: Secret, Rule: "default:fail-closed"}
}
