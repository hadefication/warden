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
warden set APP_NAME Warden      # public keys, written directly
warden set --secret DB_PASSWORD # prompts you; the caller never sees the value
warden mcp                      # MCP server on stdio
```

Flags: `--global` targets `~/.secrets` · `--project <dir>` names the project ·
`--json` emits machine-readable output.

**Set** means present *and* non-empty. `KEY=` counts as declared-but-unset, and
`warden has KEY` exits 1 for it.

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

Create `.env.schema` beside your `.env`:

```
MY_PUBLIC_KEY=public
INTERNAL_MODE=secret
```

## How the guarantee is enforced

Three mechanisms, all checked by tests rather than convention:

- **`secret.Secret`** intercepts every `fmt` verb and `encoding/json`, so a stray
  log line or JSON encode emits `<redacted>`. `Expose()` is the single escape
  hatch, and a test caps how many production call sites may exist.
- **A canary suite** runs every command against a fixture whose values are unique
  markers and asserts none appear in stdout or stderr. Registering a new command
  without adding it to the coverage table fails the build.
- **An architecture test** asserts `internal/cli`, `internal/mcpserver` and
  `cmd/warden` never import `internal/store` directly — so no surface can reach a
  raw value without passing a classification first.

`~/.secrets` is parsed as text and never sourced; a `$(…)` in a value is read as
literal characters, not executed.

## Design

See `docs/superpowers/specs/2026-08-10-warden-design.md` and the implementation
plan in `docs/superpowers/plans/2026-08-10-warden.md`.
