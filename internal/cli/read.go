package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"
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
}

// Replaced in Task 12 by internal/cli/set.go.
func addWriteCommands(*cobra.Command, io.Writer) {}
