package query

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/hadefication/warden/internal/refs"
)

// Reference is where the code reads a key. It is re-exported so callers do not
// have to import internal/refs to read a report.
type Reference = refs.Reference

// RefOptions controls the tree walk. Root defaults to the directory holding the
// store, not the working directory — the analysis is about the project the .env
// belongs to.
type RefOptions struct {
	Root          string
	IncludeVendor bool
	Extra         []*regexp.Regexp
}

// RefReport is the comparison between what the code reads and what the file
// sets.
type RefReport struct {
	// Undeclared keys are read by the code and not set. Close to fact: if the
	// code runs, it needs them.
	Undeclared []Reference `json:"undeclared"`
	// Unused keys are set and referenced nowhere in the tree. Advisory only —
	// a key built at runtime is invisible to any static analysis.
	Unused []Row `json:"unused"`
	// Skipped files were unreadable, binary, or too large. They are a hole in
	// Unused, so a caller must say so rather than imply full coverage.
	Skipped []string `json:"skipped,omitempty"`
}

// Refs compares the tree against the store.
func (q *Q) Refs(opts RefOptions) (RefReport, error) {
	if q.global {
		return RefReport{}, fmt.Errorf("refs: %w — ~/.secrets belongs to no source tree", ErrGlobalUnsupported)
	}
	root := opts.Root
	if root == "" {
		root = filepath.Dir(q.st.Path())
	}

	res, err := refs.ScanTree(refs.Options{
		Root:          root,
		IncludeVendor: opts.IncludeVendor,
		Extra:         opts.Extra,
	})
	if err != nil {
		return RefReport{}, err
	}
	found := res.References

	rep := RefReport{Skipped: res.Skipped}
	referenced := map[string]bool{}
	undeclared := map[string]bool{}
	for _, r := range found {
		referenced[r.Key] = true
		// Only a strong reference asserts a key ought to exist. Interpolation is
		// too common a form to declare anything.
		if r.Weak || q.Has(r.Key) || undeclared[r.Key] {
			continue
		}
		undeclared[r.Key] = true
		rep.Undeclared = append(rep.Undeclared, r)
	}
	for _, row := range q.List() {
		if !referenced[row.Key] {
			rep.Unused = append(rep.Unused, row)
		}
	}
	return rep, nil
}

// DoctorWithRefs is Doctor plus the code-reference checks. It is separate
// because walking the tree costs real time, and doctor is run casually.
func (q *Q) DoctorWithRefs(opts RefOptions) []Problem {
	ps := q.Doctor()
	rep, err := q.Refs(opts)
	if err != nil {
		return ps
	}
	for _, r := range rep.Undeclared {
		ps = append(ps, Problem{
			Code:     "undeclared",
			Key:      r.Key,
			Severity: SeverityError,
			Message: fmt.Sprintf("%s is read at %s:%d and is not set",
				r.Key, r.Path, r.Line),
			Fix: setCommand(r.Key, q.Classify(r.Key).Class),
		})
	}
	for _, row := range rep.Unused {
		ps = append(ps, Problem{
			Code:     "unreferenced",
			Key:      row.Key,
			Severity: SeverityInfo,
			Message: fmt.Sprintf("%s is set and referenced nowhere in the tree "+
				"(a key built at runtime would look the same)", row.Key),
		})
	}
	return ps
}
