package query

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/webteractive/warden/internal/classify"
)

// Severity ranks a problem. It exists so a caller can gate on findings without
// matching English: --strict compares severities, never messages.
type Severity int

const (
	// SeverityInfo is worth knowing and is not a defect.
	SeverityInfo Severity = iota
	// SeverityWarn is a defect that bites when something reaches for the key.
	SeverityWarn
	// SeverityError is wrong now.
	SeverityError
)

func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarn:
		return "warn"
	default:
		return "info"
	}
}

// MarshalJSON emits the name rather than the ordinal. A consumer reading
// "severity": 1 would have to know the iota order; the tool's other JSON
// surfaces already emit classes as names, and this matches them.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Problem is one finding. Code is the machine contract; Message is prose and may
// be reworded freely. Neither ever carries a value — Fix names a command to run,
// and for a secret key that command is the prompted write, which takes no value
// argument precisely so none can appear here.
type Problem struct {
	Code     string   `json:"code"`
	Key      string   `json:"key,omitempty"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
}

// Doctor reports what is wrong with the target file, worst first.
func (q *Q) Doctor() []Problem {
	var ps []Problem
	// A declared-but-empty key also counts as missing against .env.example.
	// Reporting it under both codes doubles the output and gives the same fix
	// twice, so the more specific finding wins.
	reported := map[string]bool{}

	if st, err := os.Stat(q.Path()); err == nil && st.Mode().Perm()&0o077 != 0 {
		ps = append(ps, Problem{
			Code:     "perms",
			Severity: SeverityError,
			Message: fmt.Sprintf("%s has permissions %04o — group or world readable",
				q.Path(), st.Mode().Perm()),
			Fix: fmt.Sprintf("chmod 600 %s", q.Path()),
		})
	}

	for _, r := range q.List() {
		if !r.Set {
			ps = append(ps, Problem{
				Code:     "empty",
				Key:      r.Key,
				Severity: SeverityWarn,
				Message:  fmt.Sprintf("%s is declared but empty", r.Key),
				Fix:      setCommand(r.Key, r.Class),
			})
			reported[r.Key] = true
		}
	}

	keys, err := q.Missing()
	switch {
	case errors.Is(err, ErrGlobalUnsupported):
		// ~/.secrets has no example file to drift from. Not a finding.
	case err != nil:
		ps = append(ps, Problem{
			Code:     "no-example",
			Severity: SeverityInfo,
			Message:  "no .env.example to compare against",
		})
	default:
		for _, k := range keys {
			if reported[k] {
				continue
			}
			ps = append(ps, Problem{
				Code:     "drift",
				Key:      k,
				Severity: SeverityWarn,
				Message:  fmt.Sprintf("%s is declared in .env.example but not set", k),
				Fix:      setCommand(k, q.Classify(k).Class),
			})
		}
	}
	return ps
}

// setCommand names the command that fills a key in. The secret form deliberately
// carries no value placeholder: `set --secret` accepts no value argument.
func setCommand(key string, class classify.Class) string {
	if class == classify.Secret {
		return fmt.Sprintf("warden set --secret %s", key)
	}
	return fmt.Sprintf("warden set %s <value>", key)
}
