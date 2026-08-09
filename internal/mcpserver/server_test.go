package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/webteractive/warden/internal/prompt"
)

func project(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// connect wires a client to an in-process server, so the protocol is exercised
// without spawning a subprocess.
func connect(t *testing.T, p prompt.Prompter) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	server := New(p)
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		sb.Write(b)
	}
	return sb.String(), res.IsError
}

func TestToolsAreAdvertised(t *testing.T) {
	s := connect(t, prompt.Fake{})
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"env_has": false, "env_list": false, "env_missing": false, "env_get": false,
		"env_set": false, "env_request_secret": false, "env_classify": false,
	}
	for _, tool := range res.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %s was not advertised", name)
		}
	}
}

func TestEnvHas(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nEMPTY=\n"})
	s := connect(t, prompt.Fake{})

	got, isErr := call(t, s, "env_has", map[string]any{"key": "APP_NAME", "project": dir})
	if isErr || !strings.Contains(got, "true") {
		t.Errorf("APP_NAME: got %q isErr=%v", got, isErr)
	}
	got, _ = call(t, s, "env_has", map[string]any{"key": "EMPTY", "project": dir})
	if !strings.Contains(got, "false") {
		t.Errorf("EMPTY: got %q, want false", got)
	}
}

func TestEnvListNeverIncludesValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\nDB_PASSWORD=hunter2\n"})
	s := connect(t, prompt.Fake{})
	got, _ := call(t, s, "env_list", map[string]any{"project": dir})
	if strings.Contains(got, "hunter2") {
		t.Fatalf("env_list leaked a value: %s", got)
	}
	if !strings.Contains(got, "DB_PASSWORD") || !strings.Contains(got, "secret") {
		t.Errorf("got %s", got)
	}
}

func TestEnvGetRefusesSecrets(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=hunter2\n"})
	s := connect(t, prompt.Fake{})
	got, isErr := call(t, s, "env_get", map[string]any{"key": "DB_PASSWORD", "project": dir})
	if !isErr {
		t.Error("env_get on a secret must be an error result")
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("env_get leaked the value: %s", got)
	}
}

func TestEnvGetReturnsPublicValues(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	s := connect(t, prompt.Fake{})
	got, isErr := call(t, s, "env_get", map[string]any{"key": "APP_NAME", "project": dir})
	if isErr || !strings.Contains(got, "Warden") {
		t.Errorf("got %q isErr=%v", got, isErr)
	}
}

func TestEnvSetRefusesSecretKeys(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})
	s := connect(t, prompt.Fake{})
	got, isErr := call(t, s, "env_set", map[string]any{
		"key": "DB_PASSWORD", "value": "hunter2", "project": dir,
	})
	if !isErr {
		t.Error("env_set on a secret key must be an error result")
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("env_set echoed the attempted value: %s", got)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(b) != "DB_PASSWORD=old\n" {
		t.Errorf("nothing should have been written: %q", b)
	}
}

func TestEnvRequestSecretUsesThePromptAndConfirmsWithoutTheValue(t *testing.T) {
	dir := project(t, map[string]string{".env": "DB_PASSWORD=old\n"})
	s := connect(t, prompt.Fake{Value: "hunter2"})
	got, isErr := call(t, s, "env_request_secret", map[string]any{"key": "DB_PASSWORD", "project": dir})
	if isErr {
		t.Fatalf("unexpected error result: %s", got)
	}
	if strings.Contains(got, "hunter2") {
		t.Fatalf("env_request_secret leaked the value: %s", got)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if string(b) != "DB_PASSWORD=hunter2\n" {
		t.Errorf("got %q", b)
	}
}

func TestEnvClassifyExplains(t *testing.T) {
	dir := project(t, map[string]string{".env": "STRIPE_KEY=abc\n"})
	s := connect(t, prompt.Fake{})
	got, _ := call(t, s, "env_classify", map[string]any{"key": "STRIPE_KEY", "project": dir})
	if !strings.Contains(got, "secret") || !strings.Contains(got, "name:*_KEY") {
		t.Errorf("got %s", got)
	}
}

func TestEnvMissing(t *testing.T) {
	dir := project(t, map[string]string{
		".env":         "APP_NAME=Warden\n",
		".env.example": "APP_NAME=\nSTRIPE_SECRET=\n",
	})
	s := connect(t, prompt.Fake{})
	got, _ := call(t, s, "env_missing", map[string]any{"project": dir})
	if !strings.Contains(got, "STRIPE_SECRET") {
		t.Errorf("got %s", got)
	}
}
