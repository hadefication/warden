package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hadefication/warden/internal/query"
)

func addReadCommands(root *cobra.Command, out io.Writer) {
	root.AddCommand(&cobra.Command{
		Use:   "has <KEY>",
		Short: "exit 0 if the key is set, 1 if it is not; prints nothing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			if !q.Has(args[0]) {
				// Silent by design: an empty Msg prints nothing.
				return &ExitError{Code: CodeNo}
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "list keys with their classification and whether they are set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			rows := q.List()
			if jsonFlag(cmd) {
				type row struct {
					Key   string `json:"key"`
					Class string `json:"class"`
					Set   bool   `json:"set"`
				}
				payload := make([]row, 0, len(rows))
				for _, r := range rows {
					payload = append(payload, row{r.Key, r.Class.String(), r.Set})
				}
				return json.NewEncoder(out).Encode(payload)
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tCLASS\tSTATE")
			for _, r := range rows {
				state := "unset"
				if r.Set {
					state = "set"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Key, r.Class, state)
			}
			return tw.Flush()
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "classify <KEY>",
		Short: "explain why a key is treated as secret or public",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			r := q.Classify(args[0])
			if jsonFlag(cmd) {
				return json.NewEncoder(out).Encode(map[string]string{
					"key": args[0], "class": r.Class.String(), "rule": r.Rule,
				})
			}
			fmt.Fprintf(out, "%s\t%s\t(%s)\n", args[0], r.Class, r.Rule)
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "get <KEY>",
		Short: "print a public key's value; refuses secret keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			v, err := q.Get(args[0])
			switch {
			case errors.Is(err, query.ErrSecret):
				return &ExitError{
					Code: CodeRefused,
					Msg:  fmt.Sprintf("warden: %s is secret — its value is not readable", args[0]),
				}
			case errors.Is(err, query.ErrNotSet):
				return &ExitError{Code: CodeNo, Msg: fmt.Sprintf("warden: %s is not set", args[0])}
			case err != nil:
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			fmt.Fprintln(out, v)
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "missing",
		Short: "list keys declared in .env.example that are absent or empty in .env",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			keys, err := q.Missing()
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			if jsonFlag(cmd) {
				return json.NewEncoder(out).Encode(keys)
			}
			for _, k := range keys {
				fmt.Fprintln(out, k)
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "doctor",
		Short: "report configuration problems without revealing any value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			q, err := openQuery(cmd)
			if err != nil {
				return err
			}
			var problems []string

			if st, err := os.Stat(q.Path()); err == nil && st.Mode().Perm()&0o077 != 0 {
				problems = append(problems, fmt.Sprintf(
					"%s has permissions %04o — group or world readable; run chmod 600 on it",
					q.Path(), st.Mode().Perm()))
			}
			for _, r := range q.List() {
				if !r.Set {
					problems = append(problems, fmt.Sprintf("%s is declared but empty", r.Key))
				}
			}
			if keys, err := q.Missing(); err == nil {
				for _, k := range keys {
					problems = append(problems, fmt.Sprintf("%s is declared in .env.example but not set", k))
				}
			}

			if jsonFlag(cmd) {
				return json.NewEncoder(out).Encode(problems)
			}
			if len(problems) == 0 {
				fmt.Fprintf(out, "ok: no problems found in %s\n", q.Path())
				return nil
			}
			fmt.Fprintf(out, "%d problem(s) in %s:\n", len(problems), q.Path())
			for _, p := range problems {
				fmt.Fprintf(out, "  - %s\n", p)
			}
			return nil
		},
	})
}
