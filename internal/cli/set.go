package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
	"github.com/webteractive/warden/internal/write"
)

// SetPrompter is the channel used to collect secret values. Tests replace it
// with a prompt.Fake; nothing else should reassign it.
var SetPrompter prompt.Prompter = prompt.Default()

// SetStdin is the piped standard input, or nil when there is none.
//
// It is nil by default and wired up in main only when stdin is genuinely a
// pipe. Detecting a terminal here instead would make every `go test` run look
// piped — a test binary's stdin is not a terminal — and silently replace the
// prompter in tests that meant to exercise it.
var SetStdin io.Reader

// valueChannel resolves where a secret's value comes from, and returns a label
// naming that channel for the confirmation line.
//
// The label is not decoration. Three of these channels let warden promise the
// caller never held the value; stdin cannot, because whoever built the pipeline
// wrote it. Printing which one was used puts that difference in the transcript
// instead of leaving a reader to assume the strong case.
func valueChannel(cmd *cobra.Command) (prompt.Prompter, string, error) {
	fromFile, _ := cmd.Flags().GetString("from-file")
	generate, _ := cmd.Flags().GetBool("generate")

	if fromFile != "" && generate {
		return nil, "", errors.New(
			"--from-file and --generate both supply a value — pass only one")
	}

	switch {
	case generate:
		n, _ := cmd.Flags().GetInt("generate-length")
		return prompt.Generated{Prompter: SetPrompter, Bytes: n}, "generated", nil
	case fromFile != "":
		return prompt.File{Prompter: SetPrompter, Path: fromFile},
			"from " + filepath.Base(fromFile), nil
	case SetStdin != nil:
		return prompt.Stdin{Prompter: SetPrompter, In: SetStdin}, "from stdin", nil
	default:
		return SetPrompter, "", nil
	}
}

// refuseWardensOwnFiles rejects a --from-file that points at a file warden
// manages. Reading a key out of one to write it into another is never
// provisioning; it is the one shape that looks like exfiltration rather than
// setup. A soft guard, not a boundary — nothing stops a caller opening the file
// itself — but the obvious misuse should not be the frictionless path.
// resolve canonicalises a path for comparison, following symlinks. It returns
// "" when the path cannot be resolved, which the caller treats as "no match"
// rather than as an error — this guard exists to catch an obvious misuse, and a
// path that does not resolve is a problem the subsequent open will report
// better than a comparison can.
//
// Following symlinks is the point. filepath.Abs alone cleans "../.secrets" but
// is perfectly happy with a symlink pointing at the same file, which makes a
// guard that only calls Abs a guard against typing the path directly.
func resolve(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// A path that does not exist yet cannot be one of warden's own files,
		// which do. Fall back to the cleaned absolute path so a guarded target
		// that is momentarily unreadable still compares equal by name.
		return abs
	}
	return real
}

func refuseWardensOwnFiles(cmd *cobra.Command, source string) error {
	if source == "" {
		return nil
	}
	src := resolve(source)
	if src == "" {
		return nil
	}
	guarded := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		guarded = append(guarded, filepath.Join(home, ".secrets"))
	}
	if q, err := query.Open(scopeFrom(cmd)); err == nil {
		guarded = append(guarded, q.Path())
	}
	for _, g := range guarded {
		if abs := resolve(g); abs != "" && abs == src {
			return fmt.Errorf(
				"%s is a file warden manages — copying a key out of one store into "+
					"another is not provisioning", source)
		}
	}
	return nil
}

// channelNote renders the parenthetical on a confirmation line: "secret" alone
// for the prompt, and "secret, from stdin" or "secret, generated" when the value
// came from somewhere else.
func channelNote(class, label string) string {
	if label == "" {
		return class
	}
	return class + ", " + label
}

func addWriteCommands(root *cobra.Command, out io.Writer) {
	cmd := &cobra.Command{
		Use:   "set <KEY> [VALUE]",
		Short: "set a public key directly, or a secret key through a channel the caller does not handle",
		Long: "Set a configuration value.\n\n" +
			"Public keys take the value as an argument:\n" +
			"  warden set APP_NAME Warden\n\n" +
			"Secret keys take --secret and NO value. Where the value comes from is\n" +
			"the choice that matters, because it decides whether warden can promise\n" +
			"the caller never held it:\n\n" +
			"  warden set --secret DB_PASSWORD\n" +
			"      A prompt this process owns. The value goes keyboard to file.\n\n" +
			"  warden set --secret DB_PASSWORD --from-file ./creds.txt\n" +
			"      warden opens the file itself. The caller handles a path, not a value.\n\n" +
			"  warden set --secret API_KEY --generate\n" +
			"      warden mints it from crypto/rand. Nobody, including you, learns it.\n" +
			"      This is the answer for a credential that has already leaked.\n\n" +
			"  openssl rand -hex 32 | warden set --secret API_KEY\n" +
			"      Reads standard input. warden makes no promise about this one:\n" +
			"      whoever built the pipeline had the value first. Safe when you\n" +
			"      typed it; weaker when something else did. The confirmation line\n" +
			"      names the channel so a reader can tell which happened.\n\n" +
			"Two flags handle classification as the key is set:\n\n" +
			"  warden set --public CF_GROUP_ID abc123\n" +
			"      Record the key as public and set it, in one step. Only for a key\n" +
			"      that holds no value yet and that no rule matched — nothing can be\n" +
			"      disclosed by classifying an empty key, and a name warden only\n" +
			"      called secret by failing closed is the case this serves. A key\n" +
			"      holding a value, or one a rule recognised, needs the full\n" +
			"      ceremony: warden classify <KEY> --set public\n\n" +
			"  warden set --exposed CF_API_TOKEN abc123\n" +
			"      For a value that is already out: printed by a tool, pasted into a\n" +
			"      terminal, sitting in scrollback. Laundering it through a prompt\n" +
			"      protects nothing it has not already lost, so warden takes it on\n" +
			"      the command line — and records that it did. The key stays secret\n" +
			"      and warden get still refuses it. doctor keeps reporting it until\n" +
			"      the burned value is gone. Overwriting a key that already holds a\n" +
			"      value asks first, the way unset and clear do.",
		Args: func(cmd *cobra.Command, args []string) error {
			isSecret, _ := cmd.Flags().GetBool("secret")
			exposed, _ := cmd.Flags().GetBool("exposed")
			fromFile, _ := cmd.Flags().GetString("from-file")
			generate, _ := cmd.Flags().GetBool("generate")

			if exposed && (isSecret || fromFile != "" || generate) {
				return errors.New(
					"--exposed means the value is already out and is being typed in " +
						"deliberately; --secret, --from-file and --generate all exist to " +
						"keep a value out of sight, so combining them states two " +
						"contradictory things")
			}
			if fromFile != "" && !isSecret {
				return errors.New("--from-file needs --secret: a public value goes on " +
					"the command line, where you can read it")
			}
			if generate && !isSecret {
				return errors.New("--generate needs --secret: warden does not mint public values")
			}

			if isSecret {
				if len(args) != 1 {
					return errors.New(
						"set --secret takes exactly one argument: the key. " +
							"The value is supplied through a channel, never passed on the command line")
				}
				return nil
			}
			if len(args) != 2 {
				return errors.New("set takes two arguments: the key and its value")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			source, _ := cmd.Flags().GetString("from-file")
			if err := refuseWardensOwnFiles(cmd, source); err != nil {
				return &ExitError{Code: CodeRefused, Msg: fmt.Sprintf("warden: %v", err)}
			}

			channel, label, err := valueChannel(cmd)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}
			w, err := write.Open(scopeFrom(cmd), channel)
			if err != nil {
				return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
			}

			if isSecret, _ := cmd.Flags().GetBool("secret"); isSecret {
				switch err := w.SetSecret(key); {
				case errors.Is(err, prompt.ErrCancelled):
					return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
				case err != nil:
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				fmt.Fprintf(out, "ok: %s set (%s) in %s\n", key, channelNote("secret", label), w.Path())
				return nil
			}

			if exposed, _ := cmd.Flags().GetBool("exposed"); exposed {
				if err := w.SetExposed(key, args[1]); err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				// To stderr, so it survives a caller that only reads stdout.
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warden: %s was written from a command line, so it is now in shell "+
						"history and argv. Rotate it at the provider if it is live; "+
						"warden doctor will keep reporting it until the key is rewritten "+
						"through a channel that does not expose it.\n", key)
				fmt.Fprintf(out, "ok: %s set (secret, exposed) in %s\n", key, w.Path())
				return nil
			}

			if public, _ := cmd.Flags().GetBool("public"); public {
				if err := w.Loosen(key, args[1]); err != nil {
					if errors.Is(err, write.ErrHasValue) {
						return &ExitError{Code: CodeRefused, Msg: fmt.Sprintf(
							"warden: %s already holds a value — making a live secret "+
								"readable needs the full ceremony: "+
								"warden classify %s --set public", key, key)}
					}
					if errors.Is(err, write.ErrRuleMatched) {
						return &ExitError{Code: CodeRefused, Msg: fmt.Sprintf(
							"warden: %v.\nNothing was changed. To override the rule anyway: "+
								"warden classify %s --set public", err, key)}
					}
					if errors.Is(err, write.ErrUnwaivableShape) {
						return &ExitError{Code: CodeRefused, Msg: fmt.Sprintf(
							"warden: %s — nothing was changed", err)}
					}
					if errors.Is(err, write.ErrGlobalScope) {
						return &ExitError{Code: CodeRefused, Msg: "warden: --public is not " +
							"available with --global — ~/.secrets holds secrets by definition"}
					}
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
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
	cmd.Flags().Bool("secret", false, "take the value from a channel the caller does not handle")
	cmd.Flags().String("from-file", "",
		"read the value from this file (requires --secret; warden opens it, so the caller never holds it)")
	cmd.Flags().Bool("generate", false,
		"mint a random value (requires --secret; nobody, including you, learns it)")
	cmd.Flags().Int("generate-length", prompt.DefaultGeneratedBytes,
		"bytes of entropy for --generate, hex-encoded to twice this many characters")
	cmd.Flags().Bool("public", false,
		"record the key as public as it is set — only for a key that holds no value yet")
	cmd.Flags().Bool("exposed", false,
		"the value is already public knowledge: take it on the command line and record that it is burned")
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
