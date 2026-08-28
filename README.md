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
curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh | sh
```

This downloads the latest release for your OS and architecture, verifies its
SHA-256 checksum, and installs to `~/.local/bin/warden`. Prebuilt binaries are
published for **macOS and Linux** on **amd64 and arm64**.

Install somewhere else with `WARDEN_INSTALL_DIR`:

```sh
curl -fsSL https://raw.githubusercontent.com/webteractive/warden/main/install.sh \
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
go install github.com/webteractive/warden/cmd/warden@latest
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
warden vault set stripe/live --key STRIPE_SECRET   # store a key warden owns
warden vault list               # names, target keys, remaining time — never values
warden vault push stripe/live --to ~/Herd/app      # write it into that project's .env
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

### The vault

`.env` and `~/.secrets` hold credentials that already exist somewhere. The vault
is warden's own storage: a credential lives there once, and gets pushed into
whatever project needs it.

```sh
warden vault init [--passphrase]                 # choose the at-rest mode
warden vault set <name> --key <KEY> [--ttl 8h]   # create or replace; always prompts
warden vault list [--json]                       # names, keys, remaining time
warden vault has <name>                          # exit 0 if present and unexpired
warden vault edit <name> [--name new] [--key K] [--ttl 8h|none]
warden vault rm <name>                           # confirmation on your screen
warden vault push <name> --to <dir>|global [--as KEY] [--yes] [--force]
```

An entry is addressed by a **name** you choose and separately records the **env
key** it lands as. That indirection is what lets two projects with different
`DB_PASSWORD` values coexist as `acme/db` and `beta/db` — a store addressed by
env key can only hold one of them.

`--key` may be omitted when the name is already a valid env key, so `warden vault
set STRIPE_SECRET` needs nothing further.

**There is no `warden vault get`.** No command renders a vault value, and that is
the design rather than a refusal — nothing needs gating because nothing asks. A
value leaves the vault only through `push`, which hands it to a destination file
inside a `secret.Secret`. Exit code 2 never fires in the vault.

`push` is the operation that moves a credential from a file that exists nowhere
else into one that may well be committed, so it confirms on your screen. `--yes`
skips that on the CLI and is unavailable to the MCP server. An already-set
destination key is refused unless you pass `--force`.

### Temporary entries

`--ttl` takes `30m`, `8h`, `7d`. **The maximum is 30 days, and a longer one is
refused rather than shortened** — silently clamping would have you believe a
credential lives for a year while it dies in a month.

An expired entry is indistinguishable from one that never existed: `has` exits 1,
`list` omits it, `push` fails as absent, and it is dropped from the file at the
next write. An entry with no `--ttl` is permanent and unbounded, and that
asymmetry is the point: the cap exists to stop `--ttl 8760h` masquerading as
permanent.

### At rest

The vault is one file at `~/.warden/vault`, mode `0600`: a plaintext header
naming how to unseal it, then a single AES-256-GCM blob. Entry names are inside
the seal, because `acme/prod-db` is itself worth not leaking.

The master key lives in your OS keyring by default — the macOS Keychain, or
libsecret on Linux — which is what keeps every other command free of a passphrase
prompt. `vault init --passphrase` derives it with Argon2id instead.

**Be clear about what this buys.** Encryption at rest defends against a synced
backup, a stolen laptop with a locked keychain, a `cat ~/.warden/vault`, and an
agent grepping your home directory. It does **not** defend against a local
process: warden's release binaries are built with `CGO_ENABLED=0`, so keyring
access goes through `/usr/bin/security` and `secret-tool`, and a keychain ACL
therefore protects *those tools* rather than warden. Anything on your machine
that can run `security` can read the master key. `--passphrase` narrows that gap
at the cost of a dialog on every command, and makes the vault unusable from the
MCP server where no prompt may be available.

This is the same line warden draws everywhere else. It is written down so
"encrypted" does not imply a boundary that isn't there.

## Exit codes

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
`env_request_secret`, `env_unset`, `env_clear`, `env_classify`, plus the vault's
`vault_list`, `vault_has`, `vault_request_secret`, `vault_delete` and
`vault_push`. Every env tool takes an optional `project` path, because the
server's working directory will not reliably match the project under discussion.

Five things are deliberately CLI-only, and a test makes each omission deliberate
rather than accidental: `classify --set` (an agent may ask a key's class, never
change it), `hook` (a tool that edits the harness's own permission config is a
privilege-escalation primitive), `mcp` itself, and the vault's `init` and `edit`
(the first chooses how the vault is protected at rest; the second would let an
agent quietly extend a credential's lifetime). `vault_push` exists but cannot
skip its confirmation — `--yes` is CLI-only, and `vaultPushArgs` has no field
for it.

## How the guarantee is enforced

Four mechanisms, all checked by tests rather than convention:

- **`secret.Secret`** intercepts every `fmt` verb and `encoding/json`, so a stray
  log line or JSON encode emits `<redacted>`. `Expose()` is the single escape
  hatch, and a test caps how many production call sites may exist.
- **A canary suite** runs every command against a fixture whose values are unique
  markers and asserts none appear in stdout or stderr. Registering a new command
  without adding it to the coverage table fails the build.
- **An architecture test** asserts `internal/cli`, `internal/mcpserver` and
  `cmd/warden` never import `internal/store`, `internal/vault` or
  `internal/keyring` directly — so no surface can reach a raw value without
  passing a classification first, and none can reach the key that unseals the
  vault. A second one holds
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
`hook`, and the `vault`. Proposed but not built: `copy`, `scan`, `run`,
`example --sync`, `--file`/`diff`, rotation age, and the expanded shape rules.
