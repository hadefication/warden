package mcpserver

import (
	"context"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
)

// ToolNames is what internal/cli's parity test compares its command list
// against, and it is hand-maintained. This test proves it still describes the
// server that actually runs, so the parity check upstream cannot be satisfied by
// a stale list.
func TestToolNamesMatchesWhatTheServerAdvertises(t *testing.T) {
	res, err := connect(t, prompt.Fake{}).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	live := map[string]bool{}
	for _, tool := range res.Tools {
		live[tool.Name] = true
	}
	declared := map[string]bool{}
	for _, name := range ToolNames() {
		declared[name] = true
	}

	for name := range live {
		if !declared[name] {
			t.Errorf("tool %q is served but missing from ToolNames()", name)
		}
	}
	for name := range declared {
		if !live[name] {
			t.Errorf("ToolNames() claims %q, which the server does not serve", name)
		}
	}
}
