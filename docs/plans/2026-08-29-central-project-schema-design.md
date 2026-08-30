# Central project schema design

## Goal

Keep classification overrides in one user-owned registry without making an
override global across projects. `classify --set` must stop creating a
`.env.schema` in every repository.

## Storage

Warden stores the registry at `~/.warden/schema` as JSON. The top-level object
is keyed by canonical absolute project root; each value is a dictionary from
environment key to `public` or `secret`:

```json
{
  "/Users/example/code/shop": {
    "INTERNAL_MODE": "secret",
    "MY_PUBLIC_KEY": "public"
  }
}
```

The project root is the canonical directory containing the `.env` warden
resolved, not necessarily the caller's current directory. This avoids basename
collisions and keeps `--project` and parent-directory discovery consistent.

The registry contains no environment values. Warden creates `~/.warden` with
mode `0700` and the registry with mode `0600`, refuses to read a registry
symlink, validates the full document before use, and replaces it atomically so
an interrupted write cannot leave truncated JSON.

## Classification and compatibility

Classification remains first-match-wins:

1. recognised credential value shape, which is unwaivable;
2. the matching project entry in `~/.warden/schema`;
3. a legacy `.env.schema` beside the project's `.env`;
4. the built-in public allowlist;
5. secret-name patterns;
6. secret by default.

The central entry wins because it is the new source of truth. Existing
`.env.schema` files remain readable as a compatibility fallback, but
`classify --set` never creates or edits one. Global `~/.secrets` scope continues
to refuse reclassification because every value in that store is secret by
definition.

The classification result names the deciding layer (`user-schema`,
`project-schema`, value shape, allowlist, name pattern, or fail-closed), so a
machine-local result remains explainable in CLI and MCP output.

## Write flow and confirmation

`classify <KEY> --set public|secret` resolves the target project, rejects global
scope, and rejects attempts to waive a credential-shaped value before prompting.
It then confirms the write using `~/.warden/schema` as the displayed target and
updates only that project's dictionary entry.

The existing gate remains appropriate because the override is still scoped to
one project: making a key public requires retyping the exact key name; making it
secret uses a plain confirmation. Success output names the central registry and
the project whose entry changed.

The write remains CLI-only. MCP can read the resulting classification but
cannot create or modify an override.

## Tests

Tests prove that:

- central entries are isolated by canonical project root;
- central entries outrank legacy project schemas and built-in rules;
- value shape outranks both schema layers;
- malformed classes and malformed JSON fail closed with useful errors;
- registry creation and updates preserve unrelated projects and keys;
- symlinked registries are refused and writes are atomic;
- `classify --set` writes centrally, leaves `.env.schema` untouched, shows the
  correct target, and retains the public retype gate;
- global scope is still refused;
- CLI, MCP parity, architecture, hook, and canary guarantees remain intact.
