# Warden — `doctor --strict` and structured problems

**Date:** 2026-08-18
**Status:** implemented 2026-08-18

## Problem

`warden doctor` finds problems, prints them, and exits 0. `internal/cli/read.go:191` returns
`nil` after the loop that lists them. So doctor cannot gate anything: not a pre-deploy check, not
a CI step, not a git hook, not an `&&` in a shell one-liner. The only way to act on its output is
to read the prose and decide, which means a human, which is the interruption warden exists to
avoid.

The `--json` output has the same shape problem from the other direction: it is a flat array of
English sentences. A caller wanting to know "is the *permissions* problem present" has to
substring-match a sentence that any future rewording will break.

Doctor also swallows one answer entirely. `if keys, err := q.Missing(); err == nil` silently
drops the error, so a project with no `.env.example` is reported identically to a project whose
example file is fully satisfied. Those are very different situations and one of them is worth
saying out loud.

## Design

### Problems become values

`query` gains a `Problem`:

```go
type Problem struct {
    Code     string   // "perms", "empty", "drift", "no-example"
    Key      string   // "" for file-level problems
    Severity Severity // Error, Warn, Info
    Message  string   // human sentence, still the thing printed
    Fix      string   // "chmod 600 <path>", "warden set --secret DB_PASSWORD"
}
```

and `Doctor() []Problem` moves out of the CLI into `query`, where the MCP server can reach it
too — see the `env_doctor` spec, which depends on this one.

Text output is unchanged in shape, gaining only the fix line, because the current format is fine
and churning it would break the one thing people already read:

```
2 problem(s) in ~/Herd/app/.env:
  - error  .env has permissions 0644 — group or world readable
           fix: chmod 600 ~/Herd/app/.env
  - warn   DB_PASSWORD is declared in .env.example but not set
           fix: warden set --secret DB_PASSWORD
```

`--json` emits the struct array. That is the machine contract, and `Code` is the field callers
key on.

### Severity assignments

| Code | Severity | Why |
|---|---|---|
| `perms` | error | A group-readable `.env` is the actual vulnerability in this list. |
| `drift` | warn | A key declared in `.env.example` and not set breaks the app, but only when something reaches for it. |
| `empty` | warn | `KEY=` is usually deliberate scaffolding. |
| `no-example` | info | Worth knowing; not a defect. |

`no-example` is the fix for the swallowed error: the absence of a comparison file is now stated
rather than rendered as silence.

### `--strict`

```
warden doctor --strict          exit 1 if any error or warn problem is present
warden doctor --strict=error    exit 1 only on error problems
warden doctor --strict=warn     same as bare --strict
```

Exit **1**, not 2 or 3. 1 already means "the answer is no" across this tool — the file is not
healthy — while 2 is a policy refusal and 3 is warden failing to do its job. A parse failure or
missing `.env` still exits 3 under `--strict`, because that is warden failing, not the project.

Strict is opt-in. Making a non-zero exit the default would change the meaning of every existing
`warden doctor` call in a script or hook from "tell me" to "fail me", silently, at upgrade time.

### `--fix`

Deliberately **not** in this spec, with one exception considered and rejected: `chmod 600` is the
one fix warden could apply with no ambiguity, and it is still refused here. A tool that repairs
permissions on a file it also promises never to read invites a much larger `--fix` surface, and
the fix line already tells you the exact command. Revisit only if the copy-paste proves annoying
in practice.

## Command surface

```
warden doctor                   report; always exit 0 (unchanged)
warden doctor --strict[=level]  exit 1 when problems at or above level exist
warden doctor --json            structured problems
```

`--global` behaves as today, minus `drift` and `no-example`, which have no meaning for
`~/.secrets`.

## Invariants

No new ones. The `Fix` field is the only place this spec introduces text that could plausibly
carry a value, and it must not: the fix for an unset secret is
`warden set --secret DB_PASSWORD`, never a command with a value in it. The canary test covers
this automatically once `--strict` and the fix lines are in the invocation table.

## Testing

- Canary table entries for `doctor --strict`, `--strict=error`, and `--json` with the new shape.
- A table test mapping fixture conditions to expected `Code`/`Severity` pairs, so a reworded
  message cannot change behaviour and a changed severity cannot pass unnoticed.
- Exit-code tests: clean project → 0 under every strict level; warn-only project → 0 under
  `--strict=error`, 1 under `--strict`; missing `.env` → 3 under `--strict`.
- A project with no `.env.example` emits exactly one `no-example` info problem and exits 0 under
  `--strict`.

## Out of scope

- Duplicate-key detection, which the v1 spec listed under doctor and the implementation does not
  have. It belongs here eventually — `envfile` already knows about duplicates, and the `unset`
  spec explains why they are dangerous — but it is a separate change with its own fixture work.
- Checking whether `.env` is git-tracked. That is the `scan` spec's job, where the git plumbing
  already has to exist.

## As built (2026-08-18)

Implemented as specified, plus one thing the spec did not anticipate:

- **Each key is reported once.** A declared-but-empty key also counts as missing
  against `.env.example`, so the v1 implementation reported it under both `empty`
  and `drift` with the same fix twice. The more specific finding wins.
- `Severity` marshals as its name, not its ordinal: `"severity": 1` would make a
  consumer learn the iota order, and every other JSON surface here emits names.
- `Doctor()` moved from `internal/cli/read.go` into `internal/query`, which is
  what let the MCP surface reach it.
