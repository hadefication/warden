package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/write"
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
}
