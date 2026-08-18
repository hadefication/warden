# Warden — `scan`, finding leaked values by value

**Date:** 2026-08-18
**Status:** proposed

## Problem

The global rules say that if a secret has been exposed — committed, pasted into a transcript,
found in a world-readable file — the right response is to say so plainly and rotate it. What they
do not say is how anyone finds out.

Every existing tool for this guesses. `git-secrets`, `trufflehog` and friends look for values that
*look like* credentials, which means they find `sk_live_…` and miss the 32-character random string
that is your session key. They have to guess, because they do not know what your secrets are.

Warden does. It has the values. It can search a repository for the actual contents of `.env` and
`~/.secrets` and report matches with certainty rather than heuristics — and it can report them
**by key name**, never quoting what it found, because it knows which key each match belongs to.
No other tool can produce that output, and it is the single most useful thing warden's read
access makes possible.

## Design

```
warden scan                  working tree: tracked + untracked-not-ignored files
warden scan --staged         the staged diff only — the pre-commit gate
warden scan --history        every blob reachable from HEAD (slow, opt-in)
warden scan <path>...        named files or directories
```

Output names the key, the location, and nothing else:

```
2 finding(s) — values from ~/.secrets and ./.env appear in this repository:
  GH_TOKEN      scripts/deploy.sh:12
  DB_PASSWORD   docker-compose.override.yml:8

These values are exposed. Moving or deleting the file does not undo that —
rotate them: warden set --secret GH_TOKEN --global
```

**The matched line is never printed.** A grep-style tool prints the matching line by reflex, and
that line contains the secret. Path and line number are the entire finding. This is the detail
most likely to be "improved" by a future contributor who wants context, so it is stated as an
invariant below rather than left as a habit.

### What gets searched for

Values from both stores in scope: the project `.env` and `~/.secrets`, unioned, because a leaked
global token is not less leaked for being found in a project repo.

Only values whose key classifies **secret**. A public value appearing in the source tree is
normal and often required — `APP_NAME` is in the README, `VITE_API_URL` is compiled into a bundle.
Reporting those would bury the findings that matter.

Three further exclusions, all necessary to make the output readable:

- **Values shorter than 8 characters** are skipped. `DB_PASSWORD=secret` in a dev fixture matches
  half the codebase; a value that short is not identifiable by content anyway.
- **A stoplist of common non-identifying values** — `true`, `false`, `null`, `local`, `sync`,
  `redis`, `database`, `127.0.0.1`, `localhost`, bare integers, and single path segments. These
  reach the secret side of the classifier through key names like `SESSION_DRIVER_SECRET` and would
  otherwise match everywhere.
- **The store files themselves**, plus `.env.example`, `.env.schema`, and the meta sidecar. A
  value appearing in the file it lives in is not a finding.

`--min-length` and `--include-public` exist for the case where the defaults hide something real.

### Matching happens in-process, never via a subprocess

`git grep -F -f patternfile` would be faster and is forbidden. Values on a command line are
visible to every process on the machine via `ps`; values in a temp file are a new copy of the
secret on disk with no owner. So warden reads the candidate blobs itself and searches them in
memory with a multi-substring matcher (Aho–Corasick over the value set — one pass per file
regardless of how many values are in scope).

Git is still used, but only for *names*: `git ls-files`, `git diff --cached --name-only`,
`git rev-list` + `git cat-file` for history. Warden shells out for the file list and does the
matching itself.

Binary files are skipped by the usual NUL-byte sniff. Files above a size ceiling
(`--max-file-size`, default 8 MiB) are skipped and *reported as skipped* — a silent size cap
reads as "clean" when it is not.

### `--history`

Walks every blob reachable from every ref, which is where rotated-away credentials live. This is
the mode that answers "was this ever committed", and the answer is frequently yes for a value
someone removed from a file six months ago without rotating.

Findings from history name the commit and path:

```
  STRIPE_SECRET  a3f91c2 (2026-02-14) config/services.php:41
```

Opt-in because it is O(repository), and cached: a `.git/warden-scan-cache` recording the last
scanned rev and the set of blob OIDs already checked, so the second run only looks at new blobs.
The cache stores OIDs and never values.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings |
| 1 | findings — the answer to "is this clean" is no |
| 3 | error: no store to scan, not a git repository for `--staged`/`--history` |

1 rather than 2 because this is a report, not a refusal. That makes
`warden scan --staged || exit 1` a working pre-commit hook, which is the intended deployment —
see the `hook` spec.

## MCP surface

`env_scan {project?, mode?, paths?}` returning structured findings: `{key, path, line, commit?}`.
An agent that has just written a config file can check its own work, which is a better place for
this than a human noticing later.

## Invariants

New, and the point of the command:

1. **A finding names a key, a path, and a line. It never quotes the matched text, the matched
   line, or any surrounding context.**
2. **A value never leaves the process to reach a subprocess** — not in argv, not in a temp file,
   not on a pipe to `grep`. Git is invoked for file names only.
3. A skipped file is reported. Coverage is never silently reduced.

## Testing

- Canary table entries for every mode. The canary fixture's values are unique markers, so a
  fixture repository seeded with a canary in `deploy.sh` produces a finding whose output must not
  contain the marker — this is the canary suite doing exactly what it was built for, on the one
  command that deliberately holds a secret and a file path in the same thought.
- A test asserting the process spawns no child with a value in its argv: the git invocations go
  through an injected runner, and the test asserts every recorded argv is free of every canary.
- Multi-substring matcher unit tests: overlapping values, a value that is a prefix of another,
  values containing regex metacharacters (matching is literal), multi-line values from a PEM
  block.
- False-positive suppression: a fixture where `SESSION_SECRET=local` and `TZ_SECRET=UTC` produce
  no findings.
- `--history` on a fixture repo where a value was added and later removed, asserting the removed
  commit is still found.
- The size-cap and binary-skip paths report their skips.

## Out of scope

- Scanning anything other than the local filesystem and git history. Transcripts, shell history
  (`~/.zsh_history` is a genuinely good target and a bigger surface), CI logs, and pasted
  clipboard content all belong to later specs.
- Rotating automatically. Warden can tell you to rotate and can prompt for the new value; deciding
  a credential is dead is the user's call, and the provider's API is not warden's business.
- Entropy-based detection of secrets warden does *not* know about. That is what every other
  scanner does, and doing it worse than they do adds nothing. Warden's edge is certainty.
