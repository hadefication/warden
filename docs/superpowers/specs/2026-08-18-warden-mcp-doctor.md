# Warden — `env_doctor` and a CLI/MCP parity test

**Date:** 2026-08-18
**Status:** implemented 2026-08-18
**Depends on:** `doctor --strict` (structured `query.Problem`)

## Problem

`internal/mcpserver/server.go` mirrors the CLI one-to-one, as the design spec promises — except
it does not. There are seven tools: `env_has`, `env_list`, `env_missing`, `env_get`, `env_set`,
`env_request_secret`, `env_classify`. There is no `env_doctor`.

Doctor is the first question worth asking about an unfamiliar project. "What is wrong with the
environment here" is one call that subsumes several of the others, and it is the one an agent
cannot make over MCP. So an agent on the MCP surface has to reconstruct it: `env_list` to find
empty values, `env_missing` for drift, and no way at all to learn the file is world-readable.
That last one is the finding with actual security consequence, and it is invisible.

The deeper problem is that nothing detects this. The parity claim in the design spec is prose. A
command can be added to the CLI, covered by the canary table, shipped, and never appear on the
MCP surface — which is what happened here, and also what happened to `classify --set`, though
that one is deliberate.

## Design

### `env_doctor`

```
env_doctor {project?, global?} → []Problem
```

Returns the structured problems from `query.Doctor()` as MCP structured content, the same as
`env_list` returns rows. No text rendering: the CLI's prose format exists for humans, and an
agent wants `Code` and `Severity`.

No `strict` argument. Exit codes are a process concept; an MCP caller gets the array and decides.
Adding a boolean that changes nothing but a status the caller cannot see would be cargo cult.

### The parity test

A table in `internal/mcpserver` listing every CLI command against the tool that covers it, with
every exception named and justified in the table itself:

```go
var parity = map[string]string{
    "has":      "env_has",
    "list":     "env_list",
    "get":      "env_get",
    "missing":  "env_missing",
    "classify": "env_classify",
    "doctor":   "env_doctor",
    "set":      "env_set",          // plus env_request_secret for --secret
    "unset":    "env_unset",
    "clear":    "env_clear",
    "mcp":      "",                 // the server itself; nothing to mirror
    "hook":     "",                 // edits harness config, not env config
    "run":      "",                 // spawns a process; the harness does that
}
```

The test walks the registered cobra commands and the registered MCP tools and fails when either
side has an entry the map does not account for. An empty string is a deliberate omission and
must carry a comment — the same discipline `canary_test.go` already imposes with its `nil` entry
for `mcp`.

This is the mechanism that makes "the two surfaces cannot drift apart in what they will and will
not reveal" true rather than aspirational.

### What stays off the MCP surface

`classify --set` remains CLI-only, as the README states: an agent may ask what a key's class is
and never change it. The parity map records that as a tool-side omission with that reason, so the
next person to add a tool has to read the argument before overriding it.

`hook` and `run` are absent for a different reason. Both act on the harness or the process tree
rather than on env configuration, and an MCP server that can spawn arbitrary child processes is a
much larger thing than warden.

## Testing

- MCP stdio protocol test for `env_doctor`: a fixture with bad permissions, an empty value, and
  drift, asserting all three appear with the right codes.
- The parity test above, which fails the build on an unaccounted command or tool.
- The mcpserver leak test gains `env_doctor` — a doctor problem naming a key must never carry its
  value, and the MCP surface has its own output path that the CLI canary table does not see.

## Out of scope

- MCP resources or prompts. Warden's surface is a small set of questions and answers; tools cover
  it exactly.
- Registering the server in `~/AI/dotfiles/mcp/servers.json`, still deferred on the original
  reasoning: use the CLI until real friction decides the wording.

## As built (2026-08-18)

The parity check is two tests rather than one, because `internal/cli` imports
`internal/mcpserver` and a single test importing both ways would not compile:

- `mcpserver.ToolNames()` is a hand-maintained list, and a test in that package
  asserts it matches what a live session advertises. A stale list cannot satisfy
  the check upstream.
- `internal/cli/parity_test.go` maps commands to tools in both directions, with
  every omission carrying its reason in the table.

The old `TestToolsAreAdvertised` was deleted: it hardcoded a second tool list,
which is the drift this change exists to prevent.
