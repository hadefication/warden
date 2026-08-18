package mcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/prompt"
)

func TestEnvDoctorReportsProblemsWithoutValues(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\nDB_PASSWORD=hunter2\nEMPTY_TOKEN=\n",
		".env.example": "APP_NAME=\nDB_PASSWORD=\nNEVER_SET=\n",
	})
	if err := os.Chmod(filepath.Join(dir, ".env"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, isErr := call(t, connect(t, prompt.Fake{}), "env_doctor", map[string]any{"project": dir})
	if isErr {
		t.Fatalf("env_doctor errored: %s", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("env_doctor leaked a value: %s", got)
	}
	for _, want := range []string{"perms", "empty", "drift", "error", "warn"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in: %s", want, got)
		}
	}
}

func TestEnvDoctorIsQuietOnAHealthyProject(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n", ".env.example": "APP_NAME=\n"})
	got, isErr := call(t, connect(t, prompt.Fake{}), "env_doctor", map[string]any{"project": dir})
	if isErr {
		t.Fatalf("env_doctor errored: %s", got)
	}
	if strings.Contains(got, "perms") || strings.Contains(got, "drift") {
		t.Errorf("healthy project reported problems: %s", got)
	}
}
