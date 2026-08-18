package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/write"
)

// SetPrompter is the channel used to collect secret values. Tests replace it
// with a prompt.Fake; nothing else should reassign it.
var SetPrompter prompt.Prompter = prompt.Default()

func addWriteCommands(root *cobra.Command, out io.Writer) {
	cmd := &cobra.Command{
		Use:   "set <KEY> [VALUE]",
		Short: "set a public key directly, or a secret key through a prompt",
		Long: "Set a configuration value.\n\n" +
			"For public keys, pass the value: warden set APP_NAME Warden\n" +
			"For secret keys, pass --secret and NO value: warden set --secret DB_PASSWORD\n" +
			"The value is then typed into a prompt this process owns, so it never\n" +
			"appears on a command line, in shell history, or in a caller's output.",
		Args: func(cmd *cobra.Command, args []string) error {
			isSecret, _ := cmd.Flags().GetBool("secret")
			if isSecret {
				if len(args) != 1 {
					return errors.New(
						"set --secret takes exactly one argument: the key. " +
							"The value is typed into the prompt, never passed on the command line")
				}
				return nil
			}
			if len(args) != 2 {
				return errors.New("set takes two arguments: the key and its value")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := write.Open(scopeFrom(cmd), SetPrompter)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			key := args[0]

			if isSecret, _ := cmd.Flags().GetBool("secret"); isSecret {
				switch err := w.SetSecret(key); {
				case errors.Is(err, prompt.ErrCancelled):
					return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
				case err != nil:
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				fmt.Fprintf(out, "ok: %s set (secret) in %s\n", key, w.Path())
				return nil
			}

			if err := w.SetPublic(key, args[1]); err != nil {
				if errors.Is(err, write.ErrSecretKey) {
					return &ExitError{
						Code: CodeRefused,
						Msg: fmt.Sprintf(
							"warden: %s is secret — run: warden set --secret %s", key, key),
					}
				}
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			fmt.Fprintf(out, "ok: %s set (public) in %s\n", key, w.Path())
			return nil
		},
	}
	cmd.Flags().Bool("secret", false, "prompt for the value instead of taking it as an argument")
	root.AddCommand(cmd)

	root.AddCommand(&cobra.Command{
		Use:   "unset <KEY>",
		Short: "remove a key entirely, after confirmation",
		Long: "Remove every assignment of a key.\n\n" +
			"Every one, not the last: a duplicated key resolves to its final assignment,\n" +
			"so removing only that line would leave an earlier value live while looking\n" +
			"like it worked. Works on secret keys — deleting reveals nothing, and hand-\n" +
			"editing the file is the operation this exists to replace.\n\n" +
			"A key that currently holds a value needs confirmation on your screen.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := write.Open(scopeFrom(cmd), SetPrompter)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			n, err := w.Unset(args[0])
			if err := removalError(err, args[0], w.Path()); err != nil {
				return err
			}
			if n > 1 {
				fmt.Fprintf(out, "ok: %s removed (%d assignments) from %s\n", args[0], n, w.Path())
			} else {
				fmt.Fprintf(out, "ok: %s removed from %s\n", args[0], w.Path())
			}
			return nil
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "clear <KEY>",
		Short: "empty a key's value, keeping it declared",
		Long: "Empty a key's value while leaving the declaration in place, so it still\n" +
			"shows up in warden list as declared-but-unset. Use unset to remove it\n" +
			"entirely.\n\n" +
			"A key that currently holds a value needs confirmation on your screen.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := write.Open(scopeFrom(cmd), SetPrompter)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			if err := removalError(w.Clear(args[0]), args[0], w.Path()); err != nil {
				return err
			}
			fmt.Fprintf(out, "ok: %s cleared in %s\n", args[0], w.Path())
			return nil
		},
	})
}

// removalError maps the failures unset and clear share onto exit codes. An
// absent key is 1, the same "no" that has reports; a declined prompt is 3,
// matching a cancelled set --secret.
func removalError(err error, key, path string) error {
	switch {
	case errors.Is(err, write.ErrAbsent):
		return &ExitError{Code: CodeNo, Msg: fmt.Sprintf("warden: %s is not present in %s", key, path)}
	case errors.Is(err, prompt.ErrCancelled):
		return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
	case err != nil:
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}
	return nil
}
