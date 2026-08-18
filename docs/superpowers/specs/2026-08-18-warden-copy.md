# Warden — `copy`, a store-to-store move that never renders a value

**Date:** 2026-08-18
**Status:** proposed

## Problem

Setting up a new project means filling in credentials the user already has. `GH_TOKEN` is in
`~/.secrets`. `STRIPE_SECRET` is in the `.env` of the last four projects that needed it. Today
warden's only route into the new `.env` is `set --secret`, which opens a dialog and asks the user
to find and retype a value they stored months ago — usually by opening the very file the rules
exist to keep closed.

Warden is the one process that does not need to ask. It already reads values it will not emit:
that is exactly what makes the unwaivable shape rule possible. A value can move from one store to
another entirely inside a `secret.Secret`, never rendered, never prompted for, never on a command
line.

The reason this is not simply free is direction. Copying `~/.secrets` → a project `.env` moves a
credential from a file that exists nowhere else into a file that may well be committed. That is a
genuine exfiltration path, and it is the thing this spec has to get right.

## Design

```
warden copy <KEY> --from global                 ~/.secrets  → ./.env
warden copy <KEY> --from ~/Herd/other           other/.env  → ./.env
warden copy <KEY> --to global                   ./.env      → ~/.secrets
warden copy <KEY> --from ~/a --to ~/b           either side may be named
warden copy <KEY> --from global --as GITHUB_PAT rename in flight
```

Exactly one of `--from`/`--to` may be omitted; the omitted side is the current scope. Each takes
either `global` or a directory. `--project` still selects the default side, so
`warden copy K --from global --project ~/Herd/app` reads naturally.

The value crosses as a `secret.Secret` obtained from the source store and handed to the
destination store's `Set`. It is never formatted, never logged, never passed as an argument to
anything. Success prints the existing shape, with no value and no length:

```
ok: GH_TOKEN set (secret) in ~/Herd/app/.env — copied from ~/.secrets
```

### Authorisation

Every `copy` goes through `prompt.Confirm`, naming the key, the source path and the destination
path. The plain confirmation, not the retype variant: the value is not being unmasked, it is
being duplicated. Declining writes nothing and exits 3.

The confirmation is not optional and has no `--force`. This is the one command where the user's
screen is the only place the *direction* of the copy is ever reviewed, and direction is where the
harm lives.

### The tracked-destination refusal

Before prompting, warden asks git whether the destination file is ignored, by running
`git check-ignore --quiet <path>` in the destination directory. If the destination `.env` is
**not** ignored — meaning it is tracked, or would be picked up by the next `git add .` — the copy
is refused:

```
warden: refusing to copy GH_TOKEN into ~/Herd/app/.env — that file is not
git-ignored, so the value would be committed. Add it to .gitignore, or pass
--allow-untracked if you know the repository is private and disposable.
```

Exit 2: this is a policy refusal, the same class of answer as "the key is secret".

`--allow-untracked` exists because a scratch repo with no `.gitignore` is a real situation and a
refusal with no override becomes a reason to route around warden entirely. It is spelled
awkwardly on purpose, and the refusal names it rather than hiding it.

A destination outside any git repository is fine — `check-ignore` failing to find a repo is not a
finding.

### Guards, in order

1. Source unset or absent → exit 1, nothing written.
2. Destination file missing → exit 3 (`copy` does not create files; that is `set --create`'s job).
3. Destination not git-ignored → exit 2 unless `--allow-untracked`.
4. Confirmation declined → exit 3.
5. Overwriting a *set* destination key → the confirmation says so explicitly
   (`GH_TOKEN is already set in the destination and will be replaced`), because a copy that
   silently clobbers a working credential is the failure people will actually hit.

### Classification is not consulted for the write

`SetPublic` refuses credential-shaped values because an innocent key name is not permission to
store a live key in the clear. `copy` is the opposite case: the value is *known* to be a stored
credential and the destination is a credentials file. So `copy` uses a new
`w.CopySecret(key, secret.Secret)` path that skips the shape refusal, and does not care whether
the key classifies public or secret.

One thing it does care about: if the source value is credential-shaped and the destination key
is classified **public** by a `.env.schema` override, the copy would make a live credential
readable by `warden get`. Shape outranks the schema, so classify would refuse anyway — but the
resulting state is confusing enough to be worth naming, and `copy` warns on it.

## MCP surface

`env_copy {key, from, to, as?}`. Same prompt, same refusals. An agent can wire up a new project's
credentials end to end without ever seeing a value and without a single retype — which is the
whole point of the command.

## Implementation

- `query.Q` gains `Reveal(key) (secret.Secret, error)`, returning the wrapped value with no
  classification gate. This is a real widening of the `store` → `query` boundary and needs a
  comment saying so: it is safe only because `Secret` cannot be printed, and its single caller is
  `write.W.CopySecret`. The `Expose()` call-site cap in `internal/secret` covers the accounting.
- `write.W` gains `CopySecret(key string, v secret.Secret) error`.
- `internal/cli/copy.go` resolves the two scopes, opens a `query.Q` on the source and a `write.W`
  on the destination.

## Invariants

Invariant 1 is what this spec spends most of its care on: a value crosses process memory but
never an output stream. The new `Reveal` is the widest hole yet punched in the read path, so:

- it returns a `Secret`, not a `string` — the caller cannot print it either;
- it lives in `query` and is called only from `write`, both already permitted to hold values;
- `internal/cli` and `internal/mcpserver` must not call it, which `arch_test.go` extends to cover
  by asserting `Reveal` appears in no file under those packages.

## Testing

- Canary table entries for `copy` in both directions, plus the declined prompt, the unset source,
  and the tracked-destination refusal. The refusal message names a path and a key and must carry
  neither value.
- A cross-store round trip: value in a fixture `~/.secrets`, copied into a fixture `.env`,
  asserted by reading the destination file directly in the test — the only place a test may look
  at a value.
- `--as` renaming, including the case where the new name classifies differently from the old.
- `git check-ignore` behaviour with three fixtures: ignored destination (proceeds), untracked
  destination in a repo (refused), no repo at all (proceeds).
- The arch test extension asserting no CLI or MCP file references `Reveal`.

## Out of scope

- Copying more than one key per invocation. `copy --all` between two `.env` files is a migration
  tool, and a migration tool that moves credentials wants its own spec and its own dry run.
- Copying *from* an arbitrary file path rather than a store directory — that arrives with `--file`
  in the multi-environment spec, and `copy` picks it up for free once it exists.
