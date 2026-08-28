package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webteractive/warden/internal/prompt"
)

func TestEnvUnsetGoesThroughThePrompt(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nGH_TOKEN=abc\n"})
	asked := false
	s := connect(t, prompt.Fake{OnAction: func(string, string, string) { asked = true }})

	got, isErr := call(t, s, "env_unset", map[string]any{"key": "GH_TOKEN", "project": dir})
	if isErr {
		t.Fatalf("env_unset errored: %s", got)
	}
	if !asked {
		t.Error("an agent asking to delete a live credential must produce a dialog, not a deletion")
	}
	body, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "APP_NAME=Warden\n" {
		t.Errorf("got %q", body)
	}
}

func TestEnvUnsetReportsADeclinedPrompt(t *testing.T) {
	dir := project(t, map[string]string{".env": "GH_TOKEN=abc\n"})
	s := connect(t, prompt.Fake{ConfirmErr: prompt.ErrCancelled})

	got, isErr := call(t, s, "env_unset", map[string]any{"key": "GH_TOKEN", "project": dir})
	if !isErr {
		t.Fatalf("a declined prompt must be reported as an error, got %q", got)
	}
	if !strings.Contains(got, "cancelled") {
		t.Errorf("got %q, want a cancellation", got)
	}
}

func TestEnvClearEmptiesTheValue(t *testing.T) {
	dir := project(t, map[string]string{".env": "GH_TOKEN=abc\n"})
	got, isErr := call(t, connect(t, prompt.Fake{}), "env_clear", map[string]any{"key": "GH_TOKEN", "project": dir})
	if isErr {
		t.Fatalf("env_clear errored: %s", got)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(body) != "GH_TOKEN=\n" {
		t.Errorf("got %q", body)
	}
}
