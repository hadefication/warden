# Warden — `run`, injecting env and scrubbing what comes back

**Date:** 2026-08-18
**Status:** proposed

## Problem

Agents leak secrets through **command output**, not through `cat .env`. The rules already close
the reading path. What they do not touch is the far more common accident: a `curl -v` that echoes
its `Authorization` header, a stack trace carrying a DSN, a failing `php artisan` that dumps
config, a `docker compose config` that renders every value in the file, a `printenv` run for
unrelated reasons. Each of those puts a live credential in the transcript, and none of them
involves an agent doing anything it was told not to do.

There is a second, smaller problem. Running a command that needs a credential currently means the
agent constructing a shell line that references `$TOKEN` and hoping the variable is exported, or
sourcing the env file — which for `~/.secrets` is forbidden and for `.env` is how values end up in
shell history.

`warden run` addresses both: warden loads the environment into the child itself, and filters the
child's output on the way back.

## Design

```
warden run -- <cmd> [args...]        .env of the current project
warden run --with-global -- <cmd>    .env plus ~/.secrets (project wins on conflict)
warden run --global -- <cmd>         ~/.secrets only
warden run --only GH_TOKEN,DB_HOST -- <cmd>
```

Warden resolves the store, builds the child's environment from the parent's plus the store's
keys, and `exec`s. Values reach the child through the environment block, never through argv —
argv is world-readable via `ps`, and a command line is the one place a value must never be.

Warden performs no expansion of its own. `warden run -- echo $TOKEN` is expanded by the calling
shell before warden sees it, which is the caller's problem and not something warden can or should
intercept.

### Scrubbing

Child stdout and stderr pass through a filter that replaces every in-scope secret value with
`<redacted:KEY>`:

```
$ warden run -- curl -v https://api.example.com
> Authorization: Bearer <redacted:API_TOKEN>
```

Mechanics that matter:

- **Streaming with an overlap tail.** A value can straddle a read boundary, so the filter retains
  the last `maxValueLen - 1` bytes of each chunk and rescans across the seam. Without this, a
  value split across two reads passes through — the exact case that shows up under load and never
  in a test written carelessly.
- **The same Aho–Corasick matcher as `scan`,** built once from the value set.
- **Only secret-classified values** are scrubbed. Redacting `APP_NAME` would corrupt output for
  no gain.
- **Values shorter than 8 characters are not scrubbed,** for the reason `scan` skips them: a
  four-character value redacts half the output.
- The replacement names the key, because `<redacted>` alone tells the reader nothing and
  `<redacted:STRIPE_SECRET>` tells them exactly which credential the command was using.

### Scrubbing is best-effort, and the docs must say so loudly

A value that appears base64-encoded, percent-encoded, JSON-escaped, split across a line wrap, or
hashed will pass through untouched. `--scrub=encoded` adds base64, URL-encoding and JSON-escaping
of each value to the match set, which covers the common transformations and still misses others.

This is the same honesty the README already applies to warden as a whole: it is not a boundary,
it makes the safe path cheap. A scrubber advertised as a guarantee would be worse than no
scrubber, because it would be trusted. So:

- `warden run --help` states the limitation in its first paragraph.
- `--scrub=off` exists and is explicit.
- The README section for `run` leads with what it does not catch.

### TTY handling

With scrubbing on, the child's output goes through pipes, so programs that check `isatty` will
disable colour and progress rendering, and fully interactive programs will misbehave. Phase 1
accepts that and documents it. Phase 2 allocates a pty when warden's own stdout is a tty and
scrubs the pty stream instead, which restores interactive behaviour; it is separated because pty
handling is where portability bugs live and the feature is useful without it.

Stdin is passed through unmodified in both phases. Warden does not scrub input: the caller
supplying a secret on stdin is the caller's business, and a filter there would corrupt legitimate
data.

### Exit codes

`run` cannot use warden's 0/1/2/3 vocabulary, because the child owns the exit status and 3 is a
plausible thing for a child to return. So it follows the POSIX shell convention instead:

| Code | Meaning |
|---|---|
| 0–125 | the child's own exit status, forwarded verbatim |
| 126 | the command was found but is not executable |
| 127 | the command was not found, or warden could not resolve the store |
| 128+n | the child was killed by signal n |

This is documented as an explicit exception to warden's exit-code table, in both the README and
the table itself. An undocumented exception to a contract callers script against would be worse
than an inconsistent one.

Signals sent to warden are forwarded to the child. Warden waits for the child, flushes the
scrubber's tail buffer, and exits with the forwarded status.

## Command surface

```
warden run [--global|--with-global] [--only K,K] [--scrub=literal|encoded|off] -- <cmd> [args]
```

`--` is required before the command. Without it, cobra will claim `-v` and every other flag the
child wanted.

## MCP surface

**None.** An MCP tool that spawns arbitrary child processes is a fundamentally different and
larger thing than warden, and the harness already has a way to run commands. The parity map in
the `env_doctor` spec records `run` as a deliberate omission with this reason.

## Invariants

New:

1. A value reaches the child through its environment block only — never argv, never a temp file,
   never stdin.
2. The scrubber's seam handling means a value split across read boundaries is still replaced.
   Tested directly, with a chunk size chosen to split a canary.
3. Warden's own output on the `run` path (usage errors, exec failures) carries no value, as
   everywhere else.
4. Scrubbing is documented as best-effort at every surface that mentions it.

## Testing

- Canary table entry for `run`, including a child that deliberately prints every value it was
  given (`sh -c 'printenv'`) — the canary suite then asserts none of the secret markers reach the
  captured output. This single case is the feature's whole justification, expressed as a test.
- A seam test: a child emitting a canary value one byte per write, and another emitting it either
  side of a chunk boundary chosen to split it.
- `--scrub=off` asserts the value *does* appear, so the flag is proven to do what it claims and
  the scrubbing test is proven not to be vacuous.
- An argv test: the recorded child argv contains no value under every flag combination.
- Exit-code forwarding for 0, 42, 127 (missing command), and death by SIGTERM.
- `--only` restricting the injected set; a key absent from the store is silently absent rather
  than an error.

## Out of scope

- Wrapping long-lived services or anything Herd serves via php-fpm. The v1 spec ruled that out
  and the reasoning stands: there is no shell to wrap. `run` targets the CLI invocations an agent
  actually makes.
- Keychain-backed value references, which `run` would be the natural consumer of. See its own
  spec.
- Scrubbing anything warden did not read from a store. Warden does not know your colleague's
  token.
