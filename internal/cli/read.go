package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/query"
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

	classifyCmd := &cobra.Command{
		Use:   "classify <KEY>",
		Short: "explain why a key is treated as secret or public",
		Long: "Explain a key's classification, or record an override for it.\n\n" +
			"Without --set this only reports: warden classify APP_URL\n" +
			"With --set it records a project-scoped class in ~/.warden/schema, after\n" +
			"you authorise it\n" +
			"in a prompt this process owns. Marking a key public means warden will\n" +
			"print its value, so that direction asks you to retype the key name.\n" +
			"Value shape still wins: a recognised credential cannot be made public.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Changed, not a non-empty value: --set="" is a bad argument to an
			// explicit request, and must not quietly become a plain read.
			if cmd.Flags().Changed("set") {
				class, _ := cmd.Flags().GetString("set")
				return runReclassify(cmd, out, args[0], class)
			}
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
	}
	classifyCmd.Flags().String("set", "",
		`record a project class in ~/.warden/schema: "public" or "secret" (asks for confirmation)`)
	root.AddCommand(classifyCmd)

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

	root.AddCommand(newDoctorCmd(out))
	addRefsCommand(root, out)
}

// strictLevels maps the --strict argument to the lowest severity that fails.
var strictLevels = map[string]query.Severity{
	"warn":  query.SeverityWarn,
	"error": query.SeverityError,
}

func newDoctorCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "report configuration problems without revealing any value",
		Long: "Report configuration problems.\n\n" +
			"Bare doctor always exits 0: it reports, it does not gate. Pass --strict to\n" +
			"exit 1 when problems exist, so the command can gate a deploy or a hook.\n" +
			"--strict=error narrows that to error-severity findings only. A missing .env\n" +
			"still exits 3 under either — that is warden failing, not the project.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			threshold := query.SeverityError + 1 // higher than any severity: nothing gates
			if cmd.Flags().Changed("strict") {
				level, _ := cmd.Flags().GetString("strict")
				s, ok := strictLevels[level]
				if !ok {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf(
						"warden: unknown --strict level %q — use warn or error", level)}
				}
				threshold = s
			}

			q, err := openQuery(cmd)
			if err != nil {
				return err
			}

			withRefs, _ := cmd.Flags().GetBool("refs")
			problems := q.Doctor()
			if withRefs {
				opts, err := refOptionsFrom(cmd)
				if err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				problems = q.DoctorWithRefs(opts)
			}

			if jsonFlag(cmd) {
				if problems == nil {
					problems = []query.Problem{}
				}
				if err := json.NewEncoder(out).Encode(problems); err != nil {
					return err
				}
			} else {
				printProblems(out, q.Path(), problems)
				if !withRefs {
					// A silent omission reads as a clean bill of health.
					fmt.Fprintln(out, "(not checked: code references — pass --refs to include them)")
				}
			}

			for _, p := range problems {
				if p.Severity >= threshold {
					// Silent: the findings have already been printed.
					return &ExitError{Code: CodeNo}
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("refs", false,
		"also compare against keys the source tree reads (walks the project)")
	addRefFlags(cmd)
	cmd.Flags().String("strict", "",
		`exit 1 when problems are found: "warn" (default) or "error"`)
	// So --strict works bare as well as --strict=error.
	cmd.Flags().Lookup("strict").NoOptDefVal = "warn"
	return cmd
}

func printProblems(out io.Writer, path string, problems []query.Problem) {
	if len(problems) == 0 {
		fmt.Fprintf(out, "ok: no problems found in %s\n", path)
		return
	}
	fmt.Fprintf(out, "%d problem(s) in %s:\n", len(problems), path)
	for _, p := range problems {
		fmt.Fprintf(out, "  - %-5s %s\n", p.Severity, p.Message)
		if p.Fix != "" {
			fmt.Fprintf(out, "           fix: %s\n", p.Fix)
		}
	}
}
