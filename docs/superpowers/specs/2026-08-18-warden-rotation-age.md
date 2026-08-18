# Warden — rotation age

**Date:** 2026-08-18
**Status:** proposed

## Problem

Nobody rotates credentials, because nobody knows how old they are. The information does not exist
anywhere: a `.env` line carries no history, the file's mtime describes the last edit to *any* key,
and git does not track the file at all. So "when did we last rotate the Stripe key" is
unanswerable, and the honest answer — *probably never* — is invisible until it matters.

Warden is the only thing that writes to these files. Every `set --secret`, every `copy`, every
`unset` passes through `internal/write`. It can record when, for free, and it is the only
component in the system positioned to do so.

This also completes `scan`. A `scan` finding ends with "these values are exposed — rotate them",
and there is currently no way to confirm anyone did.

## Design

### The sidecar

A file beside the store, in exactly the format `envfile` already parses:

```
# ~/Herd/app/.env.meta   (0600, alongside .env)
STRIPE_SECRET=2026-02-14T09:12:04Z
DB_PASSWORD=2026-08-18T11:03:22Z
```

Global scope uses `~/.secrets.meta`.

Reusing the dotenv format means no new parser, no new writer, and no new atomic-save path —
`envfile.Parse` and `Save` handle it as they handle everything else. It also means the file is
trivially readable by a human, and obviously contains no secrets, which matters for a file that
will end up in backups.

Values are RFC 3339 UTC timestamps. Nothing else goes in this file: no key names warden did not
write, no counts, no provider metadata. A metadata file that grows a schema becomes a thing to
migrate.

Mode 0600 to match `.env`, and it should be gitignored — `doctor` says so if it is not.

### What gets recorded

Every warden write stamps the key: `set`, `set --secret`, `copy` (destination side), and
`classify --set` does **not** — reclassification is not rotation. `unset` and `clear` remove the
entry, because a stamp for a key that no longer exists is noise that never gets cleaned up.

**A key warden did not write has no stamp, and its age is reported as `unknown`.** Never inferred
from the file's mtime, and never backfilled at first run with "today". Both would be lies with the
same shape as the truth, and the whole value of this feature is that its answers can be trusted.
`unknown` is a useful answer — it means "warden has not seen this key change", which for a
long-lived project usually means "old".

### `warden age`

```
$ warden age
KEY                LAST WRITTEN          AGE
APP_NAME           2026-08-18T11:03Z     today
DB_PASSWORD        2026-08-18T11:03Z     today
STRIPE_SECRET      2026-02-14T09:12Z     185 days
GH_TOKEN           —                     unknown

$ warden age STRIPE_SECRET
185
```

With a key argument it prints the age in whole days to stdout and nothing else, so it composes:
`[ "$(warden age STRIPE_SECRET)" -gt 180 ] && …`. An `unknown` age prints nothing and exits 1,
consistent with every other "the answer is no" in this tool.

### `doctor` integration

A new problem code, `stale`, severity **warn**:

```
  warn   STRIPE_SECRET was last written 185 days ago (threshold 180)
         fix: warden set --secret STRIPE_SECRET
```

Threshold from `--max-age` (accepting `180d`, `6mo`, `1y`), defaulting to **365 days**. A year is
deliberately lax: a default that flags half a project's keys on first run gets the whole check
switched off.

Only **secret**-classified keys are considered. `APP_NAME` has no rotation semantics.

`unknown` ages do **not** produce a `stale` problem. They produce at most one aggregate `info`
line — `4 keys have no recorded write; warden has not changed them` — because a fresh install
would otherwise report every key as a problem on day one, which is the fastest way to make
`doctor --strict` useless.

### Is an age a leak?

No value, no length, no content. What it does reveal is activity timing — that someone touched a
credential on a particular afternoon. That is real information and worth naming, and it is
acceptable: it lives in a 0600 file beside a file with much worse consequences, and the alternative
is credentials that never rotate. Stated here so the trade is on the record rather than assumed.

## Command surface

```
warden age [KEY]               table, or whole days for one key
warden doctor --max-age 180d   staleness threshold for the stale check
```

`--global`, `--project`, `--file`, `--json` all apply. `age --json` emits
`[{key, written, ageDays}]` with `written: null` for unknown.

## MCP surface

`env_age {project?, global?, key?}` returning the same rows. This is the tool that lets an agent
notice something a human would not: that the credential it is about to debug was last written
eleven months ago.

## Implementation

- `internal/meta`, wrapping `envfile` with `Stamp(key)`, `Drop(key)`, `Get(key) (time.Time, bool)`.
  Takes a clock so tests do not sleep. No dependency on `secret` or `store` — it handles
  timestamps, and the arch test should hold it to that.
- `write.W` calls `Stamp` after a successful `st.Set`, and `Drop` after a successful `Unset`. A
  failure to write the sidecar is reported as a warning on stderr and does **not** fail the write:
  losing a timestamp is a triviality, and failing a credential write because of it would be
  absurd.
- `query.Q` reads the sidecar for `age` and for `doctor`'s `stale` check.

## Invariants

New:

1. **The meta file contains key names and timestamps. Nothing else, ever.**
2. An age warden did not observe is `unknown` and is never inferred from any other signal.
3. A sidecar write failure never fails or reverts the env write it describes.

## Testing

- Canary table entries for `age` and `doctor --max-age`. The sidecar is a new *file* warden writes,
  so — as with `example --sync` — the test reads it from disk and asserts it is canary-free.
- An injected clock driving: a fresh write is 0 days; a stamp 200 days back with a 180-day
  threshold produces `stale`; the same stamp with a 365-day threshold does not.
- `unknown` handling: a fixture with no sidecar produces no `stale` problems, one aggregate info
  line, and exit 0 under `doctor --strict`.
- `unset` drops the stamp; `classify --set` does not create one.
- A read-only directory makes the sidecar write fail while the `.env` write still succeeds, with a
  warning on stderr.
- `age KEY` exit codes: 0 with a number for a known key, 1 and silence for unknown, 1 for absent.

## Out of scope

- Asking a provider whether a credential is still valid. `warden verify STRIPE_SECRET` hitting
  Stripe's API is a genuinely good idea, needs network access, per-provider knowledge and a
  timeout policy, and belongs in its own spec.
- Rotating anything automatically. Warden prompts for the new value; the provider's side of a
  rotation is not warden's business.
- Expiry dates parsed out of the credentials themselves (JWT `exp`, AWS temporary keys). Tempting,
  and it means reading structure out of a value — a different and larger conversation.
