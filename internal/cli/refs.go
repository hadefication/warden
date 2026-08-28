package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/query"
)

// refOptionsFrom reads the tree-walk flags shared by refs and doctor --refs.
func refOptionsFrom(cmd *cobra.Command) (query.RefOptions, error) {
	vendor, _ := cmd.Flags().GetBool("include-vendor")
	raw, _ := cmd.Flags().GetStringArray("pattern")

	opts := query.RefOptions{IncludeVendor: vendor}
	for _, p := range raw {
		re, err := regexp.Compile(p)
		if err != nil {
			return opts, fmt.Errorf("bad --pattern %q: %w", p, err)
		}
		if re.NumSubexp() != 1 {
			return opts, fmt.Errorf("--pattern %q needs exactly one capture group holding the key", p)
		}
		opts.Extra = append(opts.Extra, re)
	}
	return opts, nil
}

func addRefFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("include-vendor", false, "walk vendor and node_modules too")
	cmd.Flags().StringArray("pattern", nil,
		"extra reference pattern: a regex with one capture group holding the key (repeatable)")
}

func addRefsCommand(root *cobra.Command, out io.Writer) {
	cmd := &cobra.Command{
		Use:   "refs",
		Short: "compare keys the code reads against keys the file sets",
		Long: "Compare the source tree against the env file.\n\n" +
			"undeclared: the code reads it and .env does not set it. Close to fact —\n" +
			"  if the code runs, it needs the key. This is what --strict gates on.\n" +
			"unused: set, and referenced nowhere in the tree. Advisory only: a key\n" +
			"  built at runtime, like env(\"STRIPE_{$mode}_SECRET\"), looks exactly the\n" +
			"  same. Never delete on this evidence alone — check, then warden unset.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := refOptionsFrom(cmd)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			rep, err := q.Refs(opts)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}

			onlyUndeclared, _ := cmd.Flags().GetBool("undeclared")
			onlyUnused, _ := cmd.Flags().GetBool("unused")
			showUndeclared := !onlyUnused
			showUnused := !onlyUndeclared

			if jsonFlag(cmd) {
				payload := map[string]any{}
				if showUndeclared {
					payload["undeclared"] = orEmpty(rep.Undeclared)
				}
				if showUnused {
					payload["unused"] = unusedRows(rep)
				}
				if err := json.NewEncoder(out).Encode(payload); err != nil {
					return err
				}
			} else {
				printRefs(out, rep, showUndeclared, showUnused)
			}

			if strict, _ := cmd.Flags().GetBool("strict"); strict && showUndeclared && len(rep.Undeclared) > 0 {
				return &ExitError{Code: CodeNo}
			}
			return nil
		},
	}
	cmd.Flags().Bool("undeclared", false, "only keys the code reads and the file does not set")
	cmd.Flags().Bool("unused", false, "only keys the file sets and nothing references")
	cmd.Flags().Bool("strict", false, "exit 1 when an undeclared key is found")
	addRefFlags(cmd)
	root.AddCommand(cmd)
}

func orEmpty(rs []query.Reference) []query.Reference {
	if rs == nil {
		return []query.Reference{}
	}
	return rs
}

type unusedRow struct {
	Key   string `json:"key"`
	Class string `json:"class"`
}

func unusedRows(rep query.RefReport) []unusedRow {
	rows := []unusedRow{}
	for _, r := range rep.Unused {
		rows = append(rows, unusedRow{r.Key, r.Class.String()})
	}
	return rows
}

func printRefs(out io.Writer, rep query.RefReport, showUndeclared, showUnused bool) {
	if showUndeclared {
		if len(rep.Undeclared) == 0 {
			fmt.Fprintln(out, "undeclared (0) — every key the code reads is set")
		} else {
			fmt.Fprintf(out, "undeclared (%d) — the code reads these and the file does not set them:\n",
				len(rep.Undeclared))
			for _, r := range rep.Undeclared {
				fmt.Fprintf(out, "  %-24s %s:%d\n", r.Key, r.Path, r.Line)
			}
		}
	}
	if showUnused && len(rep.Skipped) > 0 {
		// Coverage that quietly shrank would make this list look more certain
		// than it is.
		fmt.Fprintf(out, "\nnote: %d file(s) not read (binary, oversized or unreadable), "+
			"so a key referenced only there would look unused\n", len(rep.Skipped))
	}
	if showUnused && len(rep.Unused) > 0 {
		fmt.Fprintf(out, "\nunused (%d) — set, and referenced nowhere in the tree:\n", len(rep.Unused))
		for _, r := range rep.Unused {
			note := ""
			switch {
			case r.Class.String() == "secret" && r.Set:
				// Deleting is not the whole job: a live credential with no
				// consumer should be revoked at the provider, which warden
				// cannot do.
				note = "  (secret — revoke it at the provider too, then: warden unset " + r.Key + ")"
			case !r.Set:
				note = "  (declared but empty)"
			}
			fmt.Fprintf(out, "  %-24s%s\n", r.Key, note)
		}
		fmt.Fprintln(out, "\nA key built at runtime looks the same as a dead one. Check before removing.")
	}
}
