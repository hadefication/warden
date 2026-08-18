# Warden

Check and edit environment configuration without exposing secrets.

Warden answers the questions an AI agent actually needs answered about `.env` and
`~/.secrets` — *is this key set?* *what keys exist?* *what's missing?* — while
guaranteeing no secret value reaches its output. Non-sensitive keys it will set
directly. Sensitive ones it routes through a prompt on your screen, so the value
goes from your keyboard to the file without passing through the agent.

**Warden is not a security boundary.** Nothing here stops a process from running
`cat .env`. It makes the safe path fast enough to be the obvious one.

## Install

### No Go required (recommended)

Warden compiles to a single statically linked binary with no runtime dependencies,
so the installer just drops one file into place:

```sh
curl -fsSL https://raw.githubusercontent.com/hadefication/warden/main/install.sh | sh
```

This downloads the latest release for your OS and architecture, verifies its
SHA-256 checksum, and installs to `~/.local/bin/warden`. Prebuilt binaries are
published for **macOS and Linux** on **amd64 and arm64**.

Install somewhere else with `WARDEN_INSTALL_DIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/hadefication/warden/main/install.sh \
  | WARDEN_INSTALL_DIR=/usr/local/bin sh
```

> The dialog that collects secret values uses macOS `osascript`. On Linux, Warden
> falls back to a TTY prompt with echo disabled; with no TTY it refuses and prints
> the command for you to run yourself.

### From source

Requires Go 1.26+. From a clone:

```sh
./install.sh --source
```

Or without cloning:

```sh
go install github.com/hadefication/warden/cmd/warden@latest
```

### Verifying the install

```sh
warden --help
```

If the command isn't found, `~/.local/bin` isn't on your `PATH` — the installer
says so and prints the line to add to your shell profile.

## Usage

```sh
warden has STRIPE_SECRET        # exit 0 if set, 1 if not. Prints nothing.
warden list                     # keys, classification, set/unset — never values
warden get APP_NAME             # public keys only; refuses secrets
warden missing                  # keys in .env.example not filled in
warden classify APP_URL         # explains why a key is secret or public
warden doctor                   # permissions, empty values, drift
warden doctor --strict          # same, but exit 1 when there are problems
warden refs                     # keys the code reads that .env does not set
warden set APP_NAME Warden      # public keys, written directly
warden set --secret DB_PASSWORD # prompts you; the caller never sees the value
warden unset OLD_TOKEN          # remove a key, after you authorise it
warden clear OLD_TOKEN          # empty it, keeping the declaration
warden classify FOO --set public  # records an override, after you authorise it
warden hook                     # print the harness hook that redirects env reads here
warden mcp                      # MCP server on stdio
```

Flags: `--global` targets `~/.secrets` · `--project <dir>` names the project ·
`--json` emits machine-readable output.

**Set** means present *and* non-empty. `KEY=` counts as declared-but-unset, and
`warden has KEY` exits 1 for it.

### Checking a project

`doctor` reports; `doctor --strict` gates. Bare `doctor` always exits 0, so
adding `--strict` is the only thing that changes an existing script's behaviour:

```sh
warden doctor --strict          # exit 1 on any problem
warden doctor --strict=error    # exit 1 only on error-severity problems
warden doctor --refs            # also walk the source tree (slower)
```

Problems carry a stable `code` (`perms`, `empty`, `drift`, `no-example`,
`undeclared`, `unreferenced`) and a severity, so `--json` consumers key on those
rather than on the wording.

`refs` compares the source tree against the file, and needs no `.env.example` to
be right. It also says when it could not read a file, since a key referenced only
in a skipped file would look unused:

```sh
warden refs                     # both directions
warden refs --undeclared        # the code reads it, the file does not set it
warden refs --strict            # exit 1 on an undeclared key
```

**`undeclared` is close to fact** — if the code runs, it needs the key.
**`unused` is advisory**, and always will be: `env("STRIPE_{$mode}_SECRET")` is
invisible to any static analysis, so a key built at runtime looks exactly like a
dead one. There is deliberately no `--prune`; removal goes through `warden unset`
one key at a time.

### Removing a key

```sh
warden unset OLD_TOKEN          # removes every assignment of it
warden clear OLD_TOKEN          # keeps the declaration, empties the value
```

Both work on secret keys, because deleting reveals nothing — and hand-editing the
file is the operation these exist to replace. A key that currently holds a value
needs confirmation on your screen first: nothing is disclosed by a deletion, but
the value may not be recoverable, so the risk being guarded is destruction.

`unset` removes **every** assignment of the key. A duplicated key resolves to its
last assignment, so removing only that line would leave an earlier value live
while looking like it worked.

### The harness hook

`warden hook` prints a `PreToolUse` entry that denies direct reads of `.env` and
`~/.secrets` and answers with the warden command to use instead:

```sh
warden hook                       # print it; writes nothing
warden hook --install --yes       # merge it into .claude/settings.json
warden hook --install --yes --global   # ...or ~/.claude/settings.json
warden hook --check               # installed? is warden on PATH? can it run the guard?
warden hook --uninstall --yes
```

Installing preserves every other setting and every other hook, replaces warden's
own entry rather than appending a second copy, and refuses a settings file it
cannot parse rather than rewriting it.

`--check` also runs the guard on the binary it finds on `PATH`. That matters more
than it looks: the guard **fails open**, so a `warden` predating `hook` means
every read is allowed while the hook looks installed. After upgrading, reinstall
so `PATH` has the new binary.

**This is a speed bump list, not a sandbox.** It closes the path taken by
accident and teaches the replacement at the moment of need. A command can still
read a file in ways no matcher enumerates — `python -c`, a heredoc, a base64
round trip, a build script that loads dotenv. Warden is not a boundary and the
hook does not make it one.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | key absent or unset |
| 2 | refused — the key is secret |
| 3 | error — no `.env`, parse failure, cancelled prompt |

## Classification

A key is secret unless proven otherwise. Precedence, first match wins:

1. **Value shape** — `sk_live_`, `ghp_`, `AKIA`, PEM blocks, URLs carrying
   `user:pass@`. Unwaivable: a schema cannot mark a live credential public.
2. **`.env.schema` override** — optional per-project `KEY=public|secret`.
3. **Public allowlist** — framework keys like `APP_NAME`, `DB_HOST`,
   `MAIL_FROM_NAME`, and everything `VITE_*` (those ship to browsers).
4. **Secret name patterns** — `*_KEY`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*_DSN`, …
5. **Default: secret.**

Run `warden classify <KEY>` to see which rule fired.

### Overriding a classification

Either edit `.env.schema` beside your `.env` by hand:

```
MY_PUBLIC_KEY=public
INTERNAL_MODE=secret
```

…or let warden write it, which is the same file with a confirmation attached:

```sh
warden classify MY_PUBLIC_KEY --set public
warden classify INTERNAL_MODE --set secret
```

The two directions are not equally dangerous, so they are not equally easy.
Marking a key **public** is the only operation that turns a value warden refuses
to print into one it will emit, so it opens a prompt this process owns and asks
you to **retype the key name** — a button reachable by muscle memory is too weak
a gate for that. Marking a key **secret** only tightens, so it takes a plain
confirmation. Declining, mistyping, and letting the dialog time out all write
nothing and exit 3.

Two refusals land before you are asked anything:

- **`--global` is refused.** `~/.secrets` holds secrets by definition, so an
  override there would only serve to unmask one.
- **A credential-shaped value cannot be made public.** Shape outranks the schema,
  so the entry would be inert — warden refuses rather than writing a line that
  silently does nothing.

A key that is secret only by *name* is fair game: correcting `FOO_KEY` or
`SESSION_SECRET_TIMEOUT` is exactly what this is for.

`--set` is **CLI-only and deliberately absent from the MCP server**, so an agent
can ask what a key's class is but never change it.

## MCP surface

`warden mcp` serves the same surface on stdio: `env_has`, `env_list`,
`env_missing`, `env_get`, `env_doctor`, `env_refs`, `env_set`,
`env_request_secret`, `env_unset`, `env_clear`, `env_classify`. Every tool takes
an optional `project` path, because the server's working directory will not
reliably match the project under discussion.

Three things are deliberately CLI-only, and a test makes each omission
deliberate rather than accidental: `classify --set` (an agent may ask a key's
class, never change it), `hook` (a tool that edits the harness's own permission
config is a privilege-escalation primitive), and `mcp` itself.

## How the guarantee is enforced

Four mechanisms, all checked by tests rather than convention:

- **`secret.Secret`** intercepts every `fmt` verb and `encoding/json`, so a stray
  log line or JSON encode emits `<redacted>`. `Expose()` is the single escape
  hatch, and a test caps how many production call sites may exist.
- **A canary suite** runs every command against a fixture whose values are unique
  markers and asserts none appear in stdout or stderr. Registering a new command
  without adding it to the coverage table fails the build.
- **An architecture test** asserts `internal/cli`, `internal/mcpserver` and
  `cmd/warden` never import `internal/store` directly — so no surface can reach a
  raw value without passing a classification first. A second one holds
  `internal/refs` to the same line: it deals in key names and file paths, and is
  structurally unable to hold a value.
- **A parity test** maps every CLI command to the MCP tool that covers it, and
  fails the build on either side gaining something the table does not account
  for. `env_doctor` was missing for an entire release because nothing checked.

`~/.secrets` is parsed as text and never sourced; a `$(…)` in a value is read as
literal characters, not executed.

## Design

See `docs/superpowers/specs/2026-08-10-warden-design.md` and the implementation
plan in `docs/superpowers/plans/2026-08-10-warden.md`.

Later work has one spec per feature in `docs/superpowers/specs/`. Implemented:
`doctor --strict`, `env_doctor` and the parity test, `unset`/`clear`, `refs`,
and `hook`. Proposed but not built: `copy`, `scan`, `run`, `example --sync`,
`--file`/`diff`, rotation age, and the expanded shape rules.
