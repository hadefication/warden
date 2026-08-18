# Warden — `example`, keeping `.env.example` honest

**Date:** 2026-08-18
**Status:** proposed

## Problem

`warden missing` diffs `.env` against `.env.example`, and the v1 spec put editing the example file
out of scope. The result is a tool that reports drift in one direction and cannot fix it in
either. Add a key to `.env` and the example file silently falls behind; the next person to clone
the repo gets an incomplete setup, and `missing` — the command meant to catch that — reports
nothing wrong, because it only looks for keys the example declares.

The example file is also the one env-adjacent file an agent should be able to edit freely. It
contains key names and, by convention, no secrets. The reason warden has not touched it is scope,
not risk.

## Design

```
warden example              print what .env.example should contain (stdout, writes nothing)
warden example --sync       write it
warden example --check      exit 1 if the file is out of date; prints the drift
```

The default is a dry run to stdout. `--sync` is the only mode that writes, and `--check` is the
gate — the same three-mode shape as `gofmt -l` / `-w`, for the same reason: nobody should discover
what this command does by having it rewrite a tracked file.

### The one hard rule

**A value is never copied.** Every key is emitted as `KEY=`, regardless of classification,
regardless of how obviously harmless the value looks.

This is not the most convenient rule. Real example files carry defaults —
`DB_HOST=127.0.0.1`, `APP_ENV=local` — and they are genuinely useful. It is the rule anyway,
because "copy the value if it is safe" makes every future classification bug into a leak in a
committed file, and `.env.example` is committed by definition. One rule with no exceptions has
nothing to get wrong.

`--with-public-values` opts in per invocation, copying values only for keys the classifier calls
**public**. It exists because the defaults really are useful; it is off by default, it is named
explicitly at the call site, and it routes through the same classifier that gates `warden get`, so
it adds no new trust. A key that is public only via a `.env.schema` override is still copied —
that override was authorised by a human retyping the key name, which is a stronger gate than this
command needs.

### Merge semantics

`--sync` is a merge, not a regeneration:

- Keys in `.env` and not in the example are **appended**, in `.env` order, at the end.
- Keys in the example and not in `.env` are **kept**. They usually mark an optional key, or one
  the current developer has not needed yet. Removing them silently would destroy intent that lives
  nowhere else. `--prune` removes them, and reports each removal.
- Existing lines are **untouched** — comments, section headers, blank lines, ordering, existing
  values (including values a human deliberately put there). This is `envfile`'s existing
  line-preserving write, applied to a file it has not been pointed at before.
- If `.env.example` does not exist, `--sync` creates it with mode 0644 — it is meant to be
  committed and read, unlike `.env` at 0600.

### What is excluded from the example

Keys the classifier calls secret are still emitted as bare `KEY=`; that is the entire point of
declaring them. Nothing is excluded on classification grounds.

What *is* excluded: keys matching `--exclude` (repeatable glob), for the local-only keys that
should not become part of the project's setup contract — `WARDEN_*`, personal `NGROK_*`, a
teammate's debugging toggles.

### `--check`

```
$ warden example --check
.env.example is out of date:
  + MAILGUN_SECRET     set in .env, absent from .env.example
  - LEGACY_QUEUE_URL   in .env.example, no longer in .env (use --prune to remove)
```

Exit 1 on drift, 0 when in sync, 3 when there is no `.env` to compare. This makes
`warden example --check` a working CI step and pre-commit hook, and it is the mode most likely to
be used in anger.

## Command surface

```
warden example [--sync|--check] [--prune] [--with-public-values] [--exclude GLOB]...
```

`--global` is refused with exit 3: `~/.secrets` has no example counterpart, exactly as `missing`
already refuses it, and reusing that refusal keeps the two commands consistent.

`--sync` and `--check` are mutually exclusive.

## MCP surface

`env_example {project?, mode?, prune?, withPublicValues?, exclude?}`. Safe to expose in full,
including the writing mode — this is the one warden write that cannot leak a value, so it needs no
prompt. It is also the write an agent has the most legitimate reason to make: it has just added a
key to the code, and updating the example file is part of that job.

## Invariants

New, narrow, and the whole spec:

1. **`example` writes key names. Without `--with-public-values` it writes no value at all; with
   it, it writes only values the classifier calls public.**
2. A `--sync` preserves every existing byte of `.env.example` outside the lines it appends or
   (under `--prune`) removes.

## Testing

- Canary table entries for every mode, plus `--with-public-values`. The canary fixture has secret
  values on every key but `APP_NAME`; the generated example must contain none of them, and the
  test additionally reads the written `.env.example` from disk and asserts it is canary-free —
  the canary suite only watches output streams, and this command's output is a *file*. That
  extension is the important part of this spec's testing.
- Golden-file merge tests: existing example with comments and section headers, one key appended,
  ordering and comments intact.
- `--prune` removing a stale key and reporting it.
- `--check` exit codes for in-sync, drifted, and no-`.env` fixtures.
- Creation path: no example file, `--sync` creates it at 0644 while `.env` stays 0600.
- `--global` refused with exit 3.

## Out of scope

- Generating comments or descriptions for keys. Warden knows a key's name and class, not its
  meaning, and an invented comment is worse than none.
- Ordering or grouping the example file by anything other than `.env` order.
- Templating multiple example files per environment. See the multi-environment spec.
