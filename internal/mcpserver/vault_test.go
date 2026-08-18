package mcpserver

import (
	"reflect"
	"strings"
	"testing"
)

// The parity table in internal/cli names these five. A missing one there fails
// that test; a missing one here fails this test — the pair is what keeps the two
// surfaces from drifting.
func TestToolNamesIncludesTheVaultTools(t *testing.T) {
	have := map[string]bool{}
	for _, n := range ToolNames() {
		have[n] = true
	}
	for _, want := range []string{
		"vault_list", "vault_has", "vault_request_secret", "vault_delete", "vault_push",
	} {
		if !have[want] {
			t.Errorf("ToolNames is missing %q", want)
		}
	}
}

func pushArgsFieldNames() string {
	t := reflect.TypeOf(vaultPushArgs{})
	var names []string
	for i := 0; i < t.NumField(); i++ {
		names = append(names, strings.ToLower(t.Field(i).Name))
	}
	return strings.Join(names, ",")
}

// --yes lets a CLI user skip the confirmation on a push. The MCP surface must not
// be able to: the value crosses into a file that may well be committed, and the
// agent asking is not the party who should authorise that.
func TestNoVaultToolAcceptsAYesArgument(t *testing.T) {
	if strings.Contains(pushArgsFieldNames(), "yes") {
		t.Error("vaultPushArgs has a yes field — the MCP surface must never skip the confirmation")
	}
}

// A tool that mutates the vault without a value must not exist here.
func TestThereIsNoVaultSetOrEditOrInitTool(t *testing.T) {
	for _, n := range ToolNames() {
		switch n {
		case "vault_set", "vault_edit", "vault_init":
			t.Errorf("%q is registered — it is recorded CLI-only in the parity table", n)
		}
	}
}
