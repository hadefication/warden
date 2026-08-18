# Warden — `unset` and `clear`

**Date:** 2026-08-18
**Status:** implemented 2026-08-18

## Problem

Warden can add a key and change a key. It cannot remove one. `internal/write/write.go` exposes
`SetPublic` and `SetSecret` and nothing else, and `envfile.File` has `Set` with no counterpart.

So the one operation left is hand-editing the file — which is precisely what the global rules
forbid an agent from doing to `.env`, and forbid outright for `~/.secrets`. A stale
`OLD_STRIPE_KEY` sitting in a file after a migration therefore has no sanctioned removal path,
and the fallbacks are all worse than the problem: an agent running `sed -i` over a file full of
live credentials, or the user being asked to open the file themselves.

Removal is also the one write that reveals nothing. Warden does not need to read a value to
delete its line, and the confirmation says only that a key is gone. There is no disclosure risk
here at all — the risk is destruction, which is a different thing and wants a different guard.

## Design

Two verbs, because the two things people mean are genuinely different:

```
warden unset <KEY>     remove the assignment entirely; the key stops existing
warden clear <KEY>     keep the declaration, empty the value: KEY=
```

`clear` is what you want when the key must stay visible in `warden list` as declared-but-unset —
a placeholder that documents the key is expected. `unset` is what you want when the key is
obsolete. Collapsing them into one verb with a flag would make the destructive reading the
default for whichever spelling won.

### Removing *every* assignment

`envfile.Get` reads the *last* assignment for a key, matching shell semantics. So deleting only
the last line of a duplicated key would silently resurrect an older value — the most dangerous
possible outcome for this command, since it looks like a successful deletion and leaves a live
credential behind.

`Unset` therefore removes every line assigning the key, and reports the count when it is more
than one:

```
ok: OLD_TOKEN removed (2 assignments) from ~/Herd/app/.env
```

Comments above a removed line are left alone. Warden cannot know whether a comment describes the
key or the section, and guessing wrong deletes documentation.

### Authorisation

An `unset` against a key that is currently **set** goes through `prompt.Confirm` — the plain
confirmation, not the retype-the-key variant, which is reserved for the one operation that
unmasks a value. Declining writes nothing and exits 3, exactly like a cancelled `set --secret`.

An `unset` against an absent or empty key needs no confirmation: there is nothing to lose. It
exits 1 for absent (consistent with `has`) and 0 for present-but-empty, having removed the line.

`clear` never prompts when the value is already empty, and prompts when it is not — same rule,
same reason.

This is the existing pattern rather than a new one: writes whose consequences a caller should not
be able to cause unilaterally are routed through a prompt the calling process does not own.
`--force` is deliberately **not** added. A flag that skips the prompt would be discovered
immediately and then used unconditionally, which is the same as not having the prompt.

## Command surface

```
warden unset <KEY>            confirm, then remove every assignment
warden clear <KEY>            confirm, then rewrite as KEY=
```

Both accept `--global`, `--project`, `--json`. Both work on secret keys — that is the point.

Exit codes are the existing four: 0 removed, 1 key absent, 3 declined or cancelled. There is no
case for 2: refusing to delete because a key is secret would leave the file uneditable by any
sanctioned means, which is the bug this spec exists to fix.

## MCP surface

`env_unset` and `env_clear`, taking the same `{project, global, key}` arguments as `env_has`.
Both route through the same prompter, so an agent asking to delete a live credential produces a
dialog on the user's screen rather than a deletion.

## Implementation

- `envfile.File` gains `Unset(key string) int`, returning the number of lines removed. Removal
  drops the line from `f.lines`; every surviving line keeps its raw text, so `Save` still
  preserves the rest of the file byte-for-byte.
- `store.Store` gains `Unset(key string) (int, error)`.
- `write.W` gains `Unset(key)` and `Clear(key)`, each consulting `w.st.Get` only to decide
  whether the value is currently set — never to render it.
- `internal/cli/set.go` registers both commands.

## Invariants

Upheld, not extended. Specifically:

- Invariant 6 (a write preserves every byte outside the target line) now covers deletion:
  removing a line must not reflow, requote, or reorder anything else.
- Invariant 7 (a cancelled dialog is a complete no-op) covers a declined confirmation.

## Testing

- Canary table entries for `unset` and `clear` — including a declined confirmation, an absent
  key, and an empty key — or the coverage test in `internal/cli/canary_test.go` fails the build.
- A golden-file round-trip proving deletion preserves comments, blank lines, CRLF endings and
  trailing-newline state.
- **The duplicate-assignment test is the load-bearing one:** a fixture with `TOKEN=old` and
  `TOKEN=new` on separate lines, asserting `unset TOKEN` leaves no assignment at all and
  `warden has TOKEN` then exits 1.
- `~/.secrets` deletion preserving the `export ` form on surrounding lines.
- A declined prompt leaves the file byte-identical, compared as bytes rather than by re-parsing.

## Out of scope

- Removing a key from `.env.example` — see the `example --sync` spec.
- Bulk removal (`unset --all-matching PREFIX_*`). One key per invocation until a real need shows
  up; a glob that deletes credentials is a poor first draft of anything.
- Undo. Warden does not keep history, and a backup file full of old credentials would be a new
  leak surface, not a safety net.

## As built (2026-08-18)

Implemented as specified. Two things surfaced during the work:

- **`envfile.Save` now writes an empty file, not a lone newline,** when the last
  assignment is removed. The trailing-newline rule preserves the shape of a file
  with content; there is no content left to shape.
- The prompt gained `ConfirmAction(action, key, path)` rather than reusing
  `Confirm`, whose wording is specific to recording a class. Deletion gets the
  plain ceremony; the retype stays reserved for the one operation that unmasks a
  value.
- `internal/cli` gained a `TestMain` that defaults `SetPrompter` to the fake. A
  write test without one does not fail — it opens a real macOS dialog and waits
  60 seconds for a prompt nobody is looking at.
