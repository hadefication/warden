package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/hadefication/warden/internal/classify"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/write"
)

// parseClass maps the --set argument onto a class. The two spellings match what
// .env.schema itself accepts, so what the user types is what lands in the file.
func parseClass(s string) (classify.Class, error) {
	switch s {
	case "public":
		return classify.Public, nil
	case "secret":
		return classify.Secret, nil
	}
	return classify.Secret, fmt.Errorf("unknown class %q — use \"public\" or \"secret\"", s)
}

// runReclassify handles `classify <KEY> --set <class>`.
//
// This is deliberately reachable only from the CLI. Marking a key public is the
// one operation that turns a value warden refuses to print into one it will
// emit, so authorising it belongs with the human at the terminal — there is no
// MCP tool for it, and internal/mcpserver never calls this.
func runReclassify(cmd *cobra.Command, out io.Writer, key, class string) error {
	to, err := parseClass(class)
	if err != nil {
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}

	w, err := write.Open(scopeFrom(cmd), SetPrompter)
	if err != nil {
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}

	switch err := w.Reclassify(key, to); {
	case errors.Is(err, write.ErrGlobalScope):
		return &ExitError{
			Code: CodeRefused,
			Msg: "warden: --set is not available with --global — " +
				"~/.secrets holds secrets by definition, so keys there are always secret",
		}
	case errors.Is(err, write.ErrUnwaivableShape):
		// The wrapped error names the rule that fired, never the value.
		return &ExitError{Code: CodeRefused, Msg: fmt.Sprintf("warden: %v", err)}
	case errors.Is(err, prompt.ErrCancelled):
		return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
	case err != nil:
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}

	if jsonFlag(cmd) {
		return json.NewEncoder(out).Encode(map[string]string{
			"key": key, "class": to.String(), "path": w.SchemaPath(),
		})
	}
	// Say what the change enables. For public that is the whole consequence, and
	// leaving it implicit is how someone discovers it by accident later.
	consequence := fmt.Sprintf("warden get %s will now print its value", key)
	if to == classify.Secret {
		consequence = fmt.Sprintf("warden get %s is now refused", key)
	}
	fmt.Fprintf(out, "ok: %s = %s in %s — %s\n", key, to, w.SchemaPath(), consequence)
	return nil
}
