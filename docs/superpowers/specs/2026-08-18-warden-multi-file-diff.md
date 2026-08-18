# Warden — `--file`, `--env`, and `diff`

**Date:** 2026-08-18
**Status:** proposed

## Problem

Warden knows two files: the nearest `.env` and `~/.secrets`. Real projects have more —
`.env.staging`, `.env.testing`, `.env.production.local`, `.env.docker` — and the v1 spec put them
out of scope. The consequence is that the single most common real question about them cannot be
asked at all: *staging is broken and local is fine; which keys differ?*

Today the only way to answer that is to open both files side by side, which is the forbidden
operation performed twice. And it is a question warden is uniquely well placed to answer, because
the useful answer is about *presence*, not content: nine times in ten the key is simply absent
from the staging file.

The plumbing is already there. `store.OpenDotenvAt(path)` takes an explicit path and nothing
calls it from the CLI.

## Design

### `--file`

A third scope selector alongside `--project` and `--global`:

```
warden list --file .env.staging
warden has STRIPE_SECRET --file ~/Herd/app/.env.production
```

Every existing command accepts it. It is mutually exclusive with `--global` and `--project`; two
scope flags together is a bug in the caller and exits 3 rather than silently picking one.

`.env.schema` is loaded from the named file's **directory**, so all files in a project share one
set of classification overrides. Per-file schemas would mean a key could be public in staging and
secret locally, which is a distinction with no legitimate use and an obvious abuse.

`missing` under `--file` compares against `.env.example` in the same directory, unchanged.

### `--env`

Sugar, because `--file .env.staging` gets typed a hundred times:

```
warden list --env staging       →  <project>/.env.staging
```

Resolved relative to the project root that `--project` (or the upward walk) found, so `--env`
composes with `--project` rather than competing with it. A missing `.env.staging` exits 3 with the
resolved path named, so a typo is diagnosable.

### `diff`

```
warden diff                            .env vs .env.example
warden diff --env staging              .env vs .env.staging
warden diff <a> <b>                    two named files
warden diff --file .env.staging --global   any two resolvable scopes
```

Output is presence and state, never content:

```
warden diff .env .env.staging

  key                  .env       .env.staging
  APP_NAME             set        set
  STRIPE_SECRET        set        absent
  MAILGUN_SECRET       set        empty
  DEPLOY_KEY           absent     set
```

`--only-differences` (the default for `--json`) drops the rows that match on both sides, which is
most of them.

### The one-bit question

Whether two sides hold the *same* value is the natural next column and is **off by default**,
behind `--values`:

```
  STRIPE_SECRET        set        set          differs
```

The v1 spec refuses to print a value's length or hash on the grounds that a length leak is still a
leak. This is a related but distinct trade, and worth stating rather than assuming:

- A length or a hash is information about **one** value, and it narrows that value's space.
- Equality is information about a **relationship** between two values, and reveals nothing about
  either — knowing local and staging share a Stripe key tells you nothing about the key.

So `--values` is defensible where `--length` is not. It is still opt-in, because it is exactly the
sort of column that grows a second use ("show me which characters differ") if it is free, and
because "are these the same" is a much rarer question than "is it there at all".

Implementation: compare the two `secret.Secret` values with `crypto/subtle.ConstantTimeCompare`
and emit a boolean. No hash is computed, so there is nothing to accidentally print — the
comparison happens in `query` and only a `bool` leaves it.

### Which scopes may be diffed

Any two, including `.env` against `~/.secrets` — that comparison answers a real question ("is this
token duplicated into the project, and should it be?") and feeds the `copy` and `scan` specs.

Diffing a file against itself exits 3 rather than printing a table of identical rows.

### Exit codes

0 when the two sides agree on presence for every key, 1 when they do not, 3 on a resolution
failure. That makes `warden diff --env staging` a deployment pre-flight check.

Under `--values`, a `differs` row does **not** affect the exit code — the two files disagreeing on
a value is normal and expected; only presence drift is a finding.

## MCP surface

`env_diff {a, b, values?}` where each side is `{project?, global?, file?}`, returning rows of
`{key, a: "set|empty|absent", b: …, differs?}`. Every existing tool gains an optional `file`
argument alongside `project` and `global`.

## Implementation

- `query.Scope` gains `File string`. `Open` resolves in precedence order File → Global → Dir, and
  errors when more than one is set rather than choosing.
- `query.Diff(a, b Scope, withValues bool) ([]DiffRow, error)` opens two `Q`s. The value
  comparison lives here so no `bool`-producing code sits outside `query`.
- `internal/cli/diff.go` for rendering.

## Invariants

Extended, carefully:

1. Invariant 1 holds unchanged: `diff` emits key names, three state words, and one boolean.
2. **The boolean is the only derived fact about a value warden will emit.** No length, no hash,
   no prefix, no first-differing-position — and any future request for one is refused with this
   line as the reason.

## Testing

- Canary table entries for `diff` across scope combinations, and for `--file`/`--env` on every
  existing command — the canary table grows by a column here, which is the intended cost of a new
  scope selector.
- Scope resolution: `--file` with `--global` exits 3; `--env` resolving relative to a `--project`
  root; a missing `--env` file naming the resolved path.
- Diff correctness on a fixture pair covering all four presence combinations plus empty-vs-set.
- `--values` on identical and differing values, asserting the output contains the word `differs`
  and neither canary.
- Exit codes: presence-identical → 0, presence-drifted → 1, `differs` under `--values` → still 0.
- `.env.schema` in the project directory applying to a `--file .env.staging` read.

## Out of scope

- Writing to two files at once, or a `sync` that copies missing keys from one env file to another.
  That is `copy` iterated, and it wants the confirmation `copy` has — a bulk credential copy
  between environments is exactly the operation that should feel slow.
- A schema per environment file.
- Discovering env files automatically and diffing all of them. `warden diff --all` reads well and
  produces an unreadable table.
