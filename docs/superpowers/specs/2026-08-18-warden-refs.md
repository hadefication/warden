# Warden — `refs`, declared against actually used

**Date:** 2026-08-18
**Status:** implemented 2026-08-18

## Problem

`warden missing` answers "which keys does `.env.example` declare that `.env` lacks". That is a
useful question with a fragile premise: it only works when someone keeps `.env.example` current,
and nobody does. A key added to the code six weeks ago and never added to the example file is
invisible to `missing`, and the failure mode is a runtime `null` in production rather than a
warning at setup time.

The source tree is the authority nobody has to maintain. `env('STRIPE_SECRET')` in the code *is*
the declaration, and it cannot drift from itself. Reading it gives warden two answers it cannot
produce today:

- **Undeclared:** the code reaches for a key that is not set. This is the real "missing", and it
  is right whether or not `.env.example` exists.
- **Unused:** a key sits in `.env` that nothing references. Usually a leftover from a migrated
  service — and if it is a credential, it is a live credential nobody is watching. Those are worth
  finding.

Neither answer involves a value. `refs` deals in key names and file paths only, which makes it the
cheapest useful thing in this batch to get right.

## Design

```
warden refs                  all three buckets
warden refs --undeclared     referenced in code, not set in .env
warden refs --unused         set in .env, referenced nowhere
warden refs --json
```

```
undeclared (2) — the code reads these and .env does not set them:
  MAILGUN_SECRET       app/Services/Mailer.php:31
  PUSHER_APP_ID        config/broadcasting.php:44

unused (1) — set in .env, referenced nowhere in the tree:
  OLD_SENTRY_DSN       (secret — verify before removing: warden unset OLD_SENTRY_DSN)
```

An unused *secret* key carries the reminder, because deleting it is not the whole job: a
credential that no longer has a consumer should be revoked at the provider too, and warden cannot
do that.

### Reference patterns

Built in, covering what the user's projects actually contain:

| Language / context | Pattern |
|---|---|
| PHP / Laravel | `env('KEY')`, `env("KEY")`, `Env::get('KEY')` |
| Node / bundlers | `process.env.KEY`, `process.env['KEY']`, `import.meta.env.KEY` |
| Go | `os.Getenv("KEY")`, `os.LookupEnv("KEY")` |
| Python | `os.environ['KEY']`, `os.environ.get('KEY')`, `getenv('KEY')` |
| Shell | `$KEY`, `${KEY}` — only for keys already known to a store, never as discovery |
| Compose / CI YAML | `${KEY}`, `KEY: ${KEY}` |

`--pattern '<regex with one capture group>'` adds a project-specific form, repeatable.

The shell/YAML row is deliberately asymmetric. `${FOO}` is far too common to treat as a
declaration, so those forms can mark a known key as *used* but can never contribute to
*undeclared*. Otherwise every `${HOME}` in a Dockerfile becomes a missing key.

### What gets walked

Tracked files plus untracked-not-ignored, same file selection as `scan`, sharing that
implementation. `vendor/`, `node_modules/`, `dist/`, `build/`, `.git/` skipped regardless of git
state. `--include-vendor` for the rare project that keeps real code there.

### `unused` is advisory and says so

Dynamic construction defeats static analysis outright:

```php
env("STRIPE_{$mode}_SECRET")     // matches nothing
config("services.{$name}.key")   // indirection through a config file
```

So `unused` is a suggestion, never a fact. Three consequences, all deliberate:

- The output says "referenced nowhere in the tree", not "unused".
- There is no `--prune`, no `--fix`, and no path from `refs` to deletion. Removal goes through
  `warden unset`, one key at a time, with its confirmation.
- `refs --unused` under `--strict` reports at **warn**, never error.

`undeclared` has the opposite bias and is much closer to fact: if the code contains
`env('MAILGUN_SECRET')` and the key is unset, something is broken now.

### Interaction with `doctor` and `missing`

`refs` does not replace `missing` — an `.env.example` still carries intent that the code does not,
like a key that is optional. Instead, `doctor` gains two problem codes from this analysis:
`undeclared` (severity error — the code needs it and it is absent) and `unreferenced` (severity
info, given how soft it is). That makes `doctor --strict` catch the real class of setup failure
without anyone maintaining an example file.

Because walking the tree costs real time, doctor runs the analysis only under
`doctor --refs`, and says in its output when it did not:

```
(not checked: code references — pass --refs to include them)
```

A silent omission would read as a clean bill of health.

### Exit codes

0 with findings by default, `--strict` for 1, matching `doctor`. `refs` is a report; the gate is
opt-in.

## MCP surface

`env_refs {project?, mode?}` returning `{undeclared: [{key, path, line}], unused: [{key, class}]}`.
This is the tool an agent should call before telling a user their setup is complete, and it is
strictly better than the `env_missing` it will mostly replace in practice.

## Implementation

Sits in a new `internal/refs` package that takes a file lister and returns key/location pairs. It
has no dependency on `store`, `query`, or `secret` — it never sees a value, and the arch test
should assert `internal/refs` imports none of them. The comparison against the store happens in
`query`, which already holds both halves.

## Testing

- Canary table entries for `refs` in each mode. Low risk by construction, and the coverage test
  requires them anyway.
- A pattern table with one fixture file per language, including the near-misses: `env('X')` inside
  a comment (still counted — comments are not parsed, and pretending otherwise needs a parser per
  language), `envelope('X')` (not counted, word-boundary anchored), `env($dynamic)` (not counted,
  and asserted so the limitation is pinned).
- An arch test asserting `internal/refs` does not import `internal/store` or `internal/secret`.
- A `doctor --refs` test asserting the two new problem codes appear, and a `doctor` test asserting
  the "not checked" line appears when they do not.

## Out of scope

- Resolving `config('services.stripe.key')` back to the `env()` call in `config/services.php`.
  Laravel's indirection is worth following eventually and needs its own pass over the config
  directory; the direct `env()` call in that file is already caught today, so the key is not
  missed, only its real consumer.
- Multi-language AST parsing. Regex over the tree is the right cost for an advisory answer.
- Suggesting values for undeclared keys.

## As built (2026-08-18)

Implemented as specified. Details settled during the work:

- `--pattern` requires exactly one capture group and is rejected at parse time,
  rather than silently matching nothing.
- The revoke reminder appears only for keys that actually hold a value. Telling
  someone to revoke a credential that is not there sends them to a provider
  dashboard for nothing.
- A reader hidden in a command substitution is still a reader: tokens are
  stripped of `$(`, backticks and quotes before being matched.
- `doctor --refs` adds `undeclared` (error) and `unreferenced` (info), and plain
  `doctor` prints a line saying it did not check.
- `ScanTree` returns the files it could not read (binary, oversized, unreadable)
  and `refs` reports the count. Coverage that quietly shrank would make the
  unused list look more certain than it is — the same rule the `scan` spec sets
  out, applied here because `unused` depends on having read everything.
