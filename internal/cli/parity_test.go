package cli

import (
	"bytes"
	"testing"

	"github.com/hadefication/warden/internal/mcpserver"
)

// parity records how each CLI command is covered on the MCP surface. An empty
// string is a deliberate omission and must carry a reason: the design promises
// the two surfaces cannot drift apart in what they will and will not reveal, and
// this table is the only thing that makes that mechanical rather than customary.
//
// env_doctor was missing for an entire release because nothing checked.
var parity = map[string]string{
	"has":      "env_has",
	"list":     "env_list",
	"get":      "env_get",
	"missing":  "env_missing",
	"classify": "env_classify", // --set is CLI-only: an agent may ask a key's class, never change it
	"doctor":   "env_doctor",
	"set":      "env_set", // plus env_request_secret for --secret
	"unset":    "env_unset",
	"clear":    "env_clear",
	"refs":     "env_refs",
	"mcp":      "", // the server itself; there is nothing to mirror
	// Deliberately CLI-only. A tool that edits the harness's own permission
	// configuration is a privilege-escalation primitive, and an agent asking to
	// relax its own restrictions is precisely what this hook exists to stop.
	"hook": "",
}

// toolOwners inverts parity, naming which command each tool answers for.
func toolOwners() map[string]string {
	owners := map[string]string{
		// Not a command of its own: set --secret routes here.
		"env_request_secret": "set --secret",
	}
	for cmd, tool := range parity {
		if tool != "" {
			owners[tool] = cmd
		}
	}
	return owners
}

func TestEveryCommandIsAccountedForOnTheMCPSurface(t *testing.T) {
	root := newRootCmd(&bytes.Buffer{}, &bytes.Buffer{})
	for _, c := range root.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if _, ok := parity[c.Name()]; !ok {
			t.Errorf("command %q has no entry in the parity table — add the MCP tool that covers it, "+
				"or map it to \"\" with a comment saying why it is deliberately CLI-only",
				c.Name())
		}
	}
}

func TestEveryMCPToolIsAccountedForOnTheCLISurface(t *testing.T) {
	owners := toolOwners()
	for _, name := range mcpserver.ToolNames() {
		if _, ok := owners[name]; !ok {
			t.Errorf("MCP tool %q answers for no CLI command — add it to the parity table", name)
		}
	}
}
