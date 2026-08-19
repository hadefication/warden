package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
	"github.com/hadefication/warden/internal/write"
)

// homeDir is where the vault lives. The vault is user-global by definition, so
// it takes no --project and refuses --global.
func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// refuseGlobal rejects --global on a vault subcommand. Ignoring the flag would
// be worse than refusing it: --global means ~/.secrets everywhere else in
// warden, and letting it pass silently here would teach it a second meaning.
func refuseGlobal(cmd *cobra.Command) error {
	if global, _ := cmd.Flags().GetBool("global"); global {
		return &ExitError{
			Code: CodeError,
			Msg: "warden: --global does not apply to the vault — the vault is already user-global, " +
				"at " + vaultPathFor(homeDir()),
		}
	}
	return nil
}

func vaultPathFor(home string) string {
	q, err := query.OpenVault(home, SetPrompter)
	if err != nil {
		// Only used for a message; a path is better than nothing.
		return home + "/.warden/vault"
	}
	return q.Path()
}

// vaultFileExists reports whether a vault has ever been written, so an error can
// say "there is no vault" rather than "there is no such entry".
func vaultFileExists() bool {
	q, err := query.OpenVault(homeDir(), SetPrompter)
	return err == nil && q.Exists()
}

// vaultErr maps a vault-layer error to an exit code. Exit code 2 is deliberately
// unreachable: it means "refused because the key is secret", and the vault has
// no read path to refuse.
func vaultErr(err error) error {
	switch {
	case errors.Is(err, prompt.ErrCancelled):
		return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
	case errors.Is(err, query.ErrNoVaultEntry) && !vaultFileExists():
		// There is no vault at all, so "no such entry" would send the user
		// looking for a name rather than telling them nothing has been created.
		return &ExitError{Code: CodeError,
			Msg: "warden: no vault yet — create an entry with: warden vault set <name> --key <KEY>"}
	default:
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}
}

func addVaultCommands(root *cobra.Command, out io.Writer) {
	v := &cobra.Command{
		Use:   "vault",
		Short: "store keys warden owns, permanently or with a deadline",
		Long: "A warden-owned store for credentials you reuse across projects.\n\n" +
			"An entry is addressed by a name you choose and records the env key it\n" +
			"lands as, so two projects with different DB_PASSWORD values can coexist.\n\n" +
			"There is no `vault get`. A value leaves the vault only through `vault push`,\n" +
			"which hands it to a destination file without ever rendering it.",
		// The parent has to be runnable to reject an unknown subcommand. Cobra
		// short-circuits a non-runnable command straight to help — before it
		// validates Args at all — so `warden vault get FOO` would print help and
		// exit 0. For a family whose premise is that no read path exists, a
		// silent success is the worst possible answer.
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return &ExitError{Code: CodeError, Msg: unknownVaultSubcommand(args[0])}
		},
	}

	v.AddCommand(vaultInitCmd(out), vaultSetCmd(out), vaultListCmd(out),
		vaultHasCmd(), vaultEditCmd(out), vaultRmCmd(out), vaultPushCmd(out))
	root.AddCommand(v)
}

// unknownVaultSubcommand explains a mistyped subcommand, and answers the
// specific question behind the ones people will actually reach for. Someone
// typing `vault get` is not making a typo — they are looking for the read path,
// and the useful reply is that there isn't one.
func unknownVaultSubcommand(name string) string {
	switch name {
	case "get", "show", "reveal", "cat", "print", "read":
		return fmt.Sprintf(
			"warden: there is no `vault %s` — the vault has no read path at all. "+
				"To use a value, push it into a file: warden vault push <name> --to <dir>", name)
	default:
		return fmt.Sprintf(
			"warden: unknown command %q for \"warden vault\" — run `warden vault --help`", name)
	}
}

func vaultInitCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create the vault, choosing how it is protected at rest",
		Long: "Create an empty vault.\n\n" +
			"By default the master key is stored in the OS keyring, which is what keeps\n" +
			"every other command free of a passphrase prompt. --passphrase derives the\n" +
			"key with Argon2id instead, which is stronger against a local process and\n" +
			"costs a dialog on every command — including from the MCP server, where a\n" +
			"prompt may be unavailable altogether.\n\n" +
			"`vault set` creates a keyring vault on its own, so this is only needed to\n" +
			"choose the passphrase mode.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			passphrase, _ := cmd.Flags().GetBool("passphrase")
			if err := write.InitVault(homeDir(), SetPrompter, passphrase); err != nil {
				return vaultErr(err)
			}
			mode := "keyring"
			if passphrase {
				mode = "passphrase (argon2id)"
			}
			fmt.Fprintf(out, "ok: vault created at %s, protected by %s\n", vaultPathFor(homeDir()), mode)
			return nil
		},
	}
	cmd.Flags().Bool("passphrase", false, "derive the key from a passphrase instead of the OS keyring")
	return cmd
}

func vaultSetCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "store a value under a name, through a prompt",
		Long: "Store a credential in the vault.\n\n" +
			"The value is always typed into a prompt this process owns — there is no\n" +
			"form of this command that takes it as an argument, so it never appears in\n" +
			"shell history or in a caller's output.\n\n" +
			"--key names the environment variable this entry lands as. It may be omitted\n" +
			"when the name is itself a valid env key, so `warden vault set STRIPE_SECRET`\n" +
			"needs nothing further.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			name := args[0]
			key, _ := cmd.Flags().GetString("key")
			if key == "" {
				if !query.LooksLikeEnvKey(name) {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf(
						"warden: %s is not a usable env key, so --key is required "+
							"(for example: warden vault set %s --key STRIPE_SECRET)", name, name)}
				}
				key = name
			}

			var ttl time.Duration
			if raw, _ := cmd.Flags().GetString("ttl"); raw != "" {
				var err error
				if ttl, err = query.ParseTTL(raw); err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
			}

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Set(name, key, ttl); err != nil {
				return vaultErr(err)
			}
			window := "permanent"
			if ttl > 0 {
				window = "expires in " + ttl.String()
			}
			fmt.Fprintf(out, "ok: %s stored (lands as %s, %s)\n", name, key, window)
			return nil
		},
	}
	cmd.Flags().String("key", "", "the env key this entry lands as")
	cmd.Flags().String("ttl", "", "delete the entry after this long (max 30d); omit for permanent")
	return cmd
}

func vaultListCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list vault entries — names, keys and remaining time, never values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			q, err := query.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			rows := q.List()

			if jsonFlag(cmd) {
				type jsonRow struct {
					Name      string     `json:"name"`
					Key       string     `json:"key"`
					Created   time.Time  `json:"created"`
					Expires   *time.Time `json:"expires,omitempty"`
					Permanent bool       `json:"permanent"`
				}
				payload := make([]jsonRow, 0, len(rows))
				for _, r := range rows {
					jr := jsonRow{Name: r.Name, Key: r.Key, Created: r.Created, Permanent: r.Permanent}
					if !r.Permanent {
						e := r.Expires
						jr.Expires = &e
					}
					payload = append(payload, jr)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"entries": payload})
			}

			if !q.Exists() {
				fmt.Fprintf(out, "no vault yet — create an entry with: warden vault set <name> --key <KEY>\n")
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintf(out, "vault is empty (%s)\n", q.Path())
				return nil
			}
			if q.Loosened() {
				fmt.Fprintf(out, "note: %s was more permissive than 0600; the next write corrects it\n", q.Path())
			}
			for _, r := range rows {
				fmt.Fprintf(out, "%-28s → %-24s %s\n", r.Name, r.Key, describeWindow(r))
			}
			return nil
		},
	}
}

// describeWindow renders the remaining time, or "permanent".
func describeWindow(r query.VaultRow) string {
	if r.Permanent {
		return "permanent"
	}
	return "expires in " + r.Expires.Sub(query.Now()).Round(time.Minute).String()
}

func vaultHasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "has <name>",
		Short: "exit 0 if a live entry exists, 1 if not — prints nothing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			q, err := query.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if !q.Has(args[0]) {
				// Empty message: has reports by exit code alone.
				return &ExitError{Code: CodeNo}
			}
			return nil
		},
	}
}

func vaultEditCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "change an entry's name, target key, or deadline",
		Long: "Change an entry's metadata. The value is never touched.\n\n" +
			"--ttl none clears a deadline, making the entry permanent. A new --ttl is\n" +
			"measured from now and is capped at 30d like any other.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			o := write.EditOpts{}
			o.NewName, _ = cmd.Flags().GetString("name")
			o.NewKey, _ = cmd.Flags().GetString("key")

			if raw, _ := cmd.Flags().GetString("ttl"); raw != "" {
				var d time.Duration
				if raw != "none" {
					var err error
					if d, err = query.ParseTTL(raw); err != nil {
						return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
					}
				}
				o.TTL = &d
			}
			if o.NewName == "" && o.NewKey == "" && o.TTL == nil {
				return &ExitError{Code: CodeError,
					Msg: "warden: nothing to change — pass --name, --key or --ttl"}
			}

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Edit(args[0], o); err != nil {
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s updated\n", args[0])
			return nil
		},
	}
	cmd.Flags().String("name", "", "rename the entry")
	cmd.Flags().String("key", "", "retarget the env key it lands as")
	cmd.Flags().String("ttl", "", "set a new window (max 30d), or `none` to make it permanent")
	return cmd
}

func vaultRmCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "remove an entry, after you authorise it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Remove(args[0]); err != nil {
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s removed\n", args[0])
			return nil
		},
	}
}

func vaultPushCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <name>",
		Short: "write an entry's value into a project's .env or ~/.secrets",
		Long: "Copy a vault entry into a destination file.\n\n" +
			"This is the only way a value leaves the vault, and it moves a credential\n" +
			"from a file that exists nowhere else into one that may well be committed —\n" +
			"so it asks on your screen first. --yes skips that.\n\n" +
			"--to takes a directory or `global`; omitted, it means the current project.\n" +
			"An already-set destination key is refused unless you pass --force.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			to, _ := cmd.Flags().GetString("to")
			dest := scopeFrom(cmd)
			switch to {
			case "":
				// scopeFrom already resolved --project or the cwd.
			case "global":
				dest.Global = true
			default:
				dest.Dir = to
			}

			as, _ := cmd.Flags().GetString("as")
			force, _ := cmd.Flags().GetBool("force")
			yes, _ := cmd.Flags().GetBool("yes")

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			res, err := w.Push(args[0], dest, as, force, yes)
			if err != nil {
				if errors.Is(err, write.ErrDestinationSet) {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s → %s in %s\n", args[0], res.Key, res.Path)
			return nil
		},
	}
	cmd.Flags().String("to", "", "destination: a directory, or `global` for ~/.secrets")
	cmd.Flags().String("as", "", "write it under a different env key")
	cmd.Flags().Bool("force", false, "overwrite a destination key that is already set")
	cmd.Flags().Bool("yes", false, "skip the on-screen confirmation")
	return cmd
}
