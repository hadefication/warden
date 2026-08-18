# Warden — `hook`, making the safe path the only one in the harness

**Date:** 2026-08-18
**Status:** implemented 2026-08-18

## Problem

The README is precise about what warden is not: *nothing here stops a process from running
`cat .env`. It makes the safe path fast enough to be the obvious one.* The thing that actually
stops it is a rule in `CLAUDE.md` — prose, read by a model, obeyed at the model's discretion. It
works most of the time, which is a different property from working.

The harness can enforce it mechanically. Claude Code's `PreToolUse` hooks see every tool call
before it runs and can deny one with an explanation. A hook that denies reads of `.env` and
`~/.secrets` and names the warden command to use instead converts a rule the model may forget into
a refusal it cannot route around by accident — and, more usefully, one that *teaches*: the denial
message is the documentation, delivered at the moment of need.

Writing that hook by hand means hand-editing `settings.json`, matching Bash commands with a
regex, and getting the allowlist right so warden itself is not blocked. It is fiddly enough that
nobody does it, which is why the tool that benefits should ship it.

## Design

```
warden hook                  print the hook JSON to stdout (default; writes nothing)
warden hook --install        merge it into .claude/settings.json
warden hook --install --global   merge into ~/.claude/settings.json
warden hook --check          is it installed, and is warden on PATH?
warden hook --uninstall      remove the block warden added
```

Print-by-default for the same reason `example` dry-runs: a command that silently edits a settings
file is a command nobody trusts twice.

### What the hook denies

A `PreToolUse` matcher on `Read` and `Bash`.

**Read:** any path whose basename matches `.env`, `.env.*`, or `.secrets`, with `.env.example` and
`.env.schema` explicitly exempted — those are meant to be read, and blocking them is the fastest
way to have the hook removed in irritation.

**Bash:** a command that names an `.env`/`.secrets` path *and* invokes one of a reader list —
`cat`, `head`, `tail`, `less`, `more`, `bat`, `grep`, `rg`, `sed`, `awk`, `strings`, `xxd`, `od`,
`open`, `code`, `vim`, `nano`, `source`, `.`, `printenv`, `env`. Plus the specific shapes that
launder a read: `while read` loops over the file, `export $(cat .env …)`, `xargs < .env`.

**Never denied:** any command whose first word is `warden`. Warden reads these files; that is the
point. The allowlist is a prefix match on the resolved first token, not a substring — a substring
match would wave through `cat .env && warden list`.

### The denial message is the feature

```
Denied: reading .env directly. Use warden, which answers this without exposing values:
  warden has KEY          is it set?           (exit 0/1)
  warden list             keys + class + state
  warden missing          declared but unset
  warden doctor           what's wrong here
  warden get KEY          public keys only
  warden set --secret KEY user types the value; you never see it
```

An unexplained denial produces three more attempts at a workaround. A denial that names the
replacement produces the replacement.

### `--check`

```
$ warden hook --check
hook:    installed in ~/.claude/settings.json (warden v0.4.1)
warden:  ~/.local/bin/warden — on PATH
matcher: Read, Bash
```

Exit 0 when installed and warden is reachable, 1 when either is missing. The PATH check matters:
a hook that denies `cat .env` and recommends a command that is not installed is strictly worse
than no hook.

### Merging, not overwriting

`--install` reads the existing settings file, adds warden's hook entry to the `PreToolUse` array,
and writes it back — preserving every other key and every other hook. Warden's entry is tagged so
`--uninstall` and re-`--install` can find exactly it:

```json
{ "_warden": "env-read-guard", "matcher": "Read|Bash", "hooks": [ … ] }
```

Re-installing replaces the tagged entry rather than appending a second copy. A malformed settings
file is a refusal (exit 3) with the parse error, never a rewrite — warden is not repairing
somebody's JSON.

`--install` prints a diff of what it will change and asks for confirmation through
`prompt.Confirm`. Editing a harness's configuration is a bigger intervention than warden's usual
business and should be seen before it happens.

### Other harnesses

`--target claude` (default), `codex`, `cursor`. Each writes the same policy in that harness's own
format; unsupported targets exit 3 naming what is supported rather than writing a Claude-shaped
file somewhere it means nothing.

### Honesty about what this is

The pattern list is a speed bump list, not a sandbox. A command can read a file in ways no matcher
enumerates — `python -c`, a heredoc, a base64 round trip, a build script that loads dotenv, an
editor extension. `warden hook --help` says exactly that, in the same register the README uses for
warden as a whole. The value is that the *accidental* path is closed and the replacement is taught;
claiming containment would be false, and a false claim here is worse than no hook, because someone
would rely on it.

Warden must never describe this hook as security. That is a documentation invariant, and it is the
one most likely to erode.

## Command surface

```
warden hook [--install|--check|--uninstall] [--global] [--target claude|codex|cursor]
```

No `--project`/`--file`/`--json` scope flags: this command configures a harness, not an env file.
`--json` on `--check` is reasonable and included.

## MCP surface

**None.** A tool that edits the harness's own permission configuration is a privilege-escalation
primitive, and an agent asking to relax its own restrictions is precisely the request this hook
exists to make impossible. Recorded as a deliberate omission in the parity map, with that reason.

## Invariants

New, and both about restraint:

1. Warden never describes the hook as a security boundary, in help text, README, or denial
   message.
2. `hook` writes only to the harness settings file it names, only after a shown diff and a
   confirmation, and never to a settings file it could not parse.

## Testing

- Canary table entry for `hook` in each mode (it touches no store, so the risk is low and the
  coverage test requires it regardless).
- A matcher table — the real substance. Around forty commands with expected allow/deny:
  `cat .env` deny; `cat .env.example` allow; `warden list` allow; `cat .env && warden list` deny;
  `grep -r FOO src/` allow; `grep TOKEN .env` deny; `source ~/.secrets` deny;
  `echo "$HOME/.secrets"` allow (naming a path is not reading it); `sed -i s/a/b/ .env` deny.
  Each row is a decision someone will otherwise re-litigate.
- Merge tests: existing unrelated hooks preserved; re-install replaces rather than duplicates;
  malformed JSON refused with the file left byte-identical.
- `--check` exit codes with warden present and absent from a stubbed PATH.
- A test asserting the strings "secure", "prevents", and "security boundary" appear nowhere in this
  command's help or messages. Pinning invariant 1 in a test is heavy-handed, and it is the only way
  a documentation invariant survives contact with future edits.

## Out of scope

- Blocking *writes* to `.env`. The rules already permit direct edits when the user asks, and a
  write guard would collide with that permission.
- A hook that rewrites a denied command into the warden equivalent automatically. Guessing which
  warden command someone meant by `grep TOKEN .env` is a guess, and a wrong rewrite is worse than
  a denial.
- Shipping this in dotfiles' `rules/` — the rules stay prose and stay in force; the hook is the
  mechanical layer under them. Deciding they should reference each other is the deferred
  rule-rewrite the v1 spec already parked.

## As built (2026-08-18)

Three deviations from this spec, each forced by how the harness actually works:

- **The matcher lives in warden, not in `settings.json`.** A `PreToolUse` matcher
  selects on *tool name* only; it cannot express "a Bash command that reads
  `.env`". So the installed entry runs `warden hook --guard`, which reads the
  tool-call payload on stdin and decides. That also makes the whole matcher table
  a plain unit test rather than a regex embedded in someone's config.
- **`--install` takes `--yes` instead of opening a confirmation dialog.** The
  prompt package speaks in keys and env files; bolting a third ceremony onto it
  for a settings-file edit would have distorted it. Printing the exact block and
  requiring a second, explicit invocation is the same gate without the distortion.
- **The matcher covers `Edit`, `Write` and `NotebookEdit` as well as `Read` and
  `Bash`.** Writing to `.env` through a tool that first reads it is the same
  disclosure by a different door.

Also as built: the guard **fails open** on any payload it cannot parse. A guard
that blocks every tool call in the session gets deleted, and then nothing is
guarded at all.

`--target` accepts only `claude` today; anything else exits 3 naming what is
supported.

Added during release prep, not in the original spec:

- **`--check` probes the binary on `PATH`** by running `hook --guard` against an
  empty payload. Reporting "warden is on PATH" was not enough: the installed
  binary may predate the command, and because the guard fails open, that means
  every read is allowed while the hook looks installed. This was a live case —
  the machine this was built on had exactly that stale binary.
- `LookWarden` and `GuardProbe` are injectable, because `--check` otherwise
  reports on whichever warden the test machine happens to have — the previous
  release locally, and none at all on CI, where the tests would have failed.
