// Package mcpserver exposes Warden's query and write surfaces as MCP tools.
//
// It is a thin translation layer over internal/query and internal/write — the
// same code the CLI drives — so the two surfaces cannot drift apart in what
// they will and will not reveal.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/webteractive/warden/internal/prompt"
	"github.com/webteractive/warden/internal/query"
	"github.com/webteractive/warden/internal/write"
)

// scopeArgs are the fields every tool accepts. The MCP server's working
// directory will not reliably match the project under discussion, so callers
// name it explicitly.
type scopeArgs struct {
	Project string `json:"project,omitempty" jsonschema:"directory to search for .env; defaults to the server's working directory"`
	Global  bool   `json:"global,omitempty" jsonschema:"target ~/.secrets instead of a project .env"`
}

func (a scopeArgs) scope() query.Scope {
	dir := a.Project
	if dir == "" {
		dir, _ = os.Getwd()
	}
	home, _ := os.UserHomeDir()
	return query.Scope{Global: a.Global, Dir: dir, Home: home}
}

type keyArgs struct {
	scopeArgs
	Key string `json:"key" jsonschema:"the environment variable name"`
}

type setArgs struct {
	scopeArgs
	Key   string `json:"key" jsonschema:"the environment variable name"`
	Value string `json:"value" jsonschema:"the value to write; rejected if the key or the value is sensitive"`
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errResult(format string, a ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, a...)}},
	}
}

// New builds the MCP server. p is the channel used to collect secret values.
func New(p prompt.Prompter) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "warden", Version: version}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_has",
		Description: "Report whether an environment key is set (present and non-empty). " +
			"Works for secret keys too — it never reveals the value. Use this instead of reading .env.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		set := q.Has(a.Key)
		return textResult(fmt.Sprintf("%t", set)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_list",
		Description: "List every key in the target file with its classification (public or secret) " +
			"and whether it is set. Values are never included.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		type row struct {
			Key   string `json:"key"`
			Class string `json:"class"`
			Set   bool   `json:"set"`
		}
		rows := []row{}
		for _, r := range q.List() {
			rows = append(rows, row{r.Key, r.Class.String(), r.Set})
		}
		return nil, rows, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "env_missing",
		Description: "List keys declared in .env.example that are absent or empty in .env. Project scope only.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a scopeArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		keys, err := q.Missing()
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if keys == nil {
			keys = []string{}
		}
		return nil, keys, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_get",
		Description: "Read the value of a PUBLIC key. Secret keys are refused — use env_has to check " +
			"whether one is set, or env_request_secret to have the user fill it in.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		v, err := q.Get(a.Key)
		switch {
		case errors.Is(err, query.ErrSecret):
			return errResult("warden: %s is secret — its value is not readable", a.Key), nil, nil
		case errors.Is(err, query.ErrNotSet):
			return errResult("warden: %s is not set", a.Key), nil, nil
		case err != nil:
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(v), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_set",
		Description: "Set a PUBLIC key's value. Refused if the key is classified secret, or if the " +
			"supplied value itself looks like a credential.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a setArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.SetPublic(a.Key, a.Value); err != nil {
			if errors.Is(err, write.ErrSecretKey) {
				return errResult(
					"warden: %s is secret — call env_request_secret instead so the user types the value",
					a.Key), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s set (public) in %s", a.Key, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "env_request_secret",
		Description: "Ask the user to type a secret value into a prompt on their screen, and write it. " +
			"You never see the value — only a confirmation. Use this for any sensitive key.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.Open(a.scope(), p)
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.SetSecret(a.Key); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was written"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("ok: %s set (secret) in %s", a.Key, w.Path())), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "env_classify",
		Description: "Explain whether a key is treated as public or secret, and which rule decided it.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a keyArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.Open(a.scope())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		r := q.Classify(a.Key)
		return nil, map[string]string{"key": a.Key, "class": r.Class.String(), "rule": r.Rule}, nil
	})

	return s
}

// Serve runs the server on stdio.
func Serve(ctx context.Context, p prompt.Prompter) error {
	return New(p).Run(ctx, &mcp.StdioTransport{})
}
