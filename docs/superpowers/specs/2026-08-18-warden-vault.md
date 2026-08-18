# Warden — `vault`, an encrypted cross-project store for keys you reuse

**Date:** 2026-08-18
**Status:** proposed

## Problem

Warden reads and writes configuration that already exists. It has no memory of its own.

That leaves the most common credential task unserved. `GH_TOKEN` lives in `~/.secrets`.
`STRIPE_SECRET` lives in the `.env` of the last four projects that needed it. Setting up the
fifth means `warden set --secret STRIPE_SECRET`, which opens a dialog and asks the user to find
and retype a value they stored months ago — usually by opening one of the very files these rules
exist to keep closed. The proposed `copy` spec addresses moving a key between two stores that
both exist. It does not address the case where the canonical home for a credential is nowhere:
scattered across project files, each copy as authoritative as the next.

A second, smaller gap: some credentials are meant to be short-lived. A scoped deploy token, a
staging password valid for the afternoon. There is nowhere to put one such that it is gone later
without the user remembering to remove it.

So: a warden-owned store where a credential can live once, permanently or with a deadline, and
from which it can be pushed into any project that needs it — without the value ever being
rendered, retyped, or handled by an agent.

## What this is not

Warden is not a security boundary, and the vault does not make it one. Encryption at rest
genuinely defends against a synced backup, a stolen laptop with a locked keychain, a `cat
~/.warden/vault`, and an agent grepping the home directory. It does not defend against a local
process that decides to shell out to `security` itself.

That last point is a direct consequence of a build constraint rather than an oversight.
`.goreleaser.yaml` sets `CGO_ENABLED=0` — which is what lets the installer drop one static file
onto a machine with no toolchain — so keyring access goes through `/usr/bin/security` and
`secret-tool` rather than the Security framework. A keychain ACL therefore protects *those
tools*, not warden specifically. Any process on the machine that can run `security` can read the
master key.

This is the same line warden already draws everywhere else, and it is written down here so the
word "encrypted" does not imply a boundary that does not exist.

## Design

### Shape of an entry

An entry is addressed by a **name** the user chooses, and separately records the **env key** it
lands as:

```
name     stripe/live
key      STRIPE_SECRET
value    (sealed)
created  2026-08-18T10:04:00Z
expires  2026-08-18T18:04:00Z   or absent, meaning permanent
```

The indirection costs one concept and buys the thing a flat store cannot do: two projects with
different `DB_PASSWORD` values coexist as `acme/db` and `beta/db`. A cross-project vault whose
address space is the env key can hold exactly one of them.

### Commands

The vault is one command family, at `~/.warden/vault`. It is inherently user-global, so
`--global` is **refused** on every subcommand rather than ignored: that flag means `~/.secrets`
everywhere else in warden and must not acquire a second meaning.

```
warden vault init [--passphrase]                 choose the at-rest mode; implicit on first set
warden vault set <name> --key <KEY> [--ttl 8h]   create or replace; always prompts
warden vault list [--json]                       names, target keys, age, remaining
warden vault has <name>                          exit 0 if present and unexpired
warden vault edit <name> [--name new] [--key K] [--ttl 8h|none]
warden vault rm <name>                           confirmation on your screen
warden vault push <name> --to <dir>|global [--as KEY] [--yes] [--force]
```

`set` creates, `list` and `has` read, `edit` changes metadata and `set` replaces a value, `rm`
deletes. That is the CRUD.

`set` **never takes a value argument.** Vault entries are secret by definition, so the value
always arrives through `internal/prompt`. There is no form of the command that puts a credential
in shell history or in argv.

Details fixed here so they are not decided twice during implementation:

- **A name matches `[A-Za-z0-9._/-]+`**, with no leading or trailing `/` and no empty segment.
  Names are keys in a JSON document rather than paths on disk, but a name carrying a newline would
  corrupt `list` output, so the charset is validated on write and a bad one exits 3.
- **`--key` may be omitted when the name is itself a valid env key** — `[A-Z_][A-Z0-9_]*`, so
  `warden vault set STRIPE_SECRET` needs nothing further. For any other name it is required, and
  its absence is an error rather than a guess: `stripe/live` has no defensible uppercasing.
- **`has` and `rm` and `push` resolve a name, never an env key.** Two entries may share a target
  key; that is the reason names exist. Lookup by key would be ambiguous by construction.
- **`--to` may be omitted from `push`**, defaulting to the current project the way `--project`
  does elsewhere. `--to global` means `~/.secrets`.
- **`list --json`** emits `{"entries":[{"name","key","created","expires","permanent"}]}` —
  `expires` absent when permanent, and no `value` field in any form.

### No read path

No command renders a vault value. There is no `vault get`, and its absence is the design rather
than a refusal: nothing needs to be gated because nothing asks. A value leaves the vault in
exactly one way — `push`, which hands it to a destination store — and it crosses as a
`secret.Secret` from `vault.Entry` into `store.Store.Set`, never formatted, never logged, never
in argv.

Exit code `2` (refused — the key is secret) therefore never fires in the vault. `1` means absent
or expired; `3` means a cancelled prompt or an unreadable vault.

### push, and the direction that matters

`push` is the point of the vault and the one operation that moves a credential from a file that
exists nowhere else into one that may well be committed. So:

- It **confirms on the user's screen** by default.
- `--yes` skips that confirmation on the CLI only, matching `hook --install --yes`. It is
  unavailable to the MCP server.
- It **refuses a destination key that is already set** unless `--force`, so a push cannot
  silently overwrite a value the project is currently using.
- `--as KEY` renames in flight, for when the entry's recorded key is not what this project calls
  it.

`edit` on an existing entry and `set` replacing a live value both destroy something that may not
be recoverable, so both take the plain `ConfirmAction` ceremony. Never the retype: that gate is
reserved for disclosure, and the vault has no disclosure path at all. Teaching the retype to mean
"confirm" is the failure mode `unset` already avoided.

`internal/prompt` gains a sentence and a run-it-yourself command per action. Its `actionSentence`
currently defaults to *"Remove %s. Its value will be gone from this file"* for anything it does not
recognise, so `push`, `replace` and `edit` would each show a dialog describing a removal — the user
would be authorising something other than what happens, which is worse than not asking. The push
sentence in particular has to name the destination, since that is the entire risk being
authorised.

### Storage format

`~/.warden/vault`, mode `0600`: a plaintext header plus one sealed blob.

```
warden-vault v1 <kdf> <base64 32-byte salt, or "-">
<base64: nonce || AES-256-GCM ciphertext>
```

The header sits outside the seal because it says *how* to unseal, never *what* is inside.
Everything else is under the ciphertext, entry names included — `acme/prod-db` is itself worth
not leaking. Plaintext under the seal:

```json
{"version":1,"entries":[
  {"name":"stripe/live","key":"STRIPE_SECRET","value":"…",
   "created":"2026-08-18T10:04:00Z","expires":"2026-08-18T18:04:00Z"}]}
```

Every write reseals the whole file, writes to a temp path, and `os.Rename`s it into place, so a
crash mid-write leaves the previous vault rather than a truncated one. At tens of entries,
whole-file resealing costs nothing and buys atomicity and metadata secrecy together.

### The master key

32 bytes from `crypto/rand`, generated on the first `vault set`, stored in the OS keyring:

```
macOS   security add-generic-password -s warden -a vault-master
Linux   secret-tool store --label=warden service warden account vault-master
```

The header's `kdf` field reads `keyring` in that case. Where no keyring exists, it reads
`argon2id` and the key is derived from a passphrase collected through `internal/prompt` — the
same channel `set --secret` uses, so the passphrase never passes through a calling agent. That
path needs `golang.org/x/crypto/argon2`, the one new dependency. AES-GCM is stdlib.

There is **no unlocked-session cache.** With a keyring there is nothing to cache. Without one,
warden already refuses when there is no TTY and prints the command for the user to run
themselves, which is the existing behaviour of every prompt in warden.

### Choosing the mode

```
warden vault init                 keyring; the default, and what happens implicitly on first set
warden vault init --passphrase    Argon2id from a passphrase, on a machine that has a keyring
```

The keyring is the default because the passphrase's advantage is narrow and its cost is broad. It
defends against a local process reading the master key — but a process running as the user can
keylog the dialog, read warden's memory, or wait for the next unlock, so it moves that attacker
from "one command" to "one command plus patience" rather than stopping them. Everything encryption
at rest genuinely defeats — a synced backup, a stolen laptop with a locked keychain, a `cat` of the
file, an agent grepping `$HOME` — the keyring defeats identically. Against the adversary the two
modes actually distinguish, warden has never claimed to be a boundary.

The cost, meanwhile, lands on the feature's main path. The prompt is an `osascript` dialog, so a
passphrase means a dialog on every `warden vault list`, and in a headless MCP context the prompt is
`ErrUnavailable` — which makes the vault unusable from the server surface this spec deliberately
exposes. A passphrase typed thirty times a day also becomes short and reused, weakening the real
key while adding the friction.

It is nonetheless selectable, because the Argon2id path must exist for the no-keyring fallback
regardless and the header already records which mode built the file. So the stronger mode costs one
flag rather than a subsystem, and nobody pays for it who did not ask.

`-T ''` on the keychain item is deliberately not used. It would make every access prompt —
including warden's own — so it buys no asymmetry. A real per-binary ACL needs the Security
framework via cgo, which costs the static binary the installer depends on, a macOS runner per arch
in CI, and a fresh prompt on every version bump since the binaries are unsigned.

`internal/keyring` owns both backends behind a `Get`/`Set`/`Delete` interface with a test fake,
so no test touches a real keychain.

### TTL

`--ttl` takes a Go duration plus `d` for days (`30m`, `8h`, `7d`), resolved to an absolute
RFC3339 UTC deadline at write time through an injected clock, so tests never sleep. Renewal on
use is deliberately out: "expires in 8h" should be a fact the user can rely on.

An expired entry is **indistinguishable from one that never existed.** `has` exits 1, `list`
omits it, `push` fails as absent. It is dropped from the file at the next reseal, whenever that
happens. `list` renders `permanent` or `expires in 3h14m`, so live temporary entries are visible.

**The maximum TTL is 30 days, and a longer one is refused rather than clamped.** Silently
shortening a requested window would be the worst option available: the user would believe a
credential lives for a year while it dies in a month, which is precisely the surprise the cap
exists to prevent. Exceeding it exits 3 and names the two honest alternatives — drop `--ttl` for a
permanent entry, or choose a window inside the cap.

The cap's real job is to stop `--ttl 8760h` being used as a permanent entry that quietly dies. An
entry with no `--ttl` is unbounded, and that asymmetry is the point: absent means "this lives here
until I remove it", stated once and plainly. A large number pretending to mean the same thing is
the failure mode, so beyond a month "temporary" is treated as a claim the design does not support.

`edit --ttl` is validated against the same cap and re-anchors the deadline from now, so an entry
can be extended indefinitely by repeated deliberate action. That is intended: each extension is a
person deciding again, in the moment, and `edit` being CLI-only is what keeps an agent out of that
loop.

### Package layout

`internal/vault` owns the format, the crypto, and the entry metadata. It is **not** a
`store.Store`: entries carry a name, a target key, and a deadline, none of which fit an interface
whose contract is "keys in file order."

`internal/cli` and `internal/mcpserver` reach the vault the way they already reach `.env` —
through `internal/query` for reads and `internal/write` for writes, never `internal/vault`
directly. The layering is unchanged; the vault is a second thing behind the same door.

### MCP surface

`vault_list`, `vault_has`, `vault_request_secret`, `vault_delete`, `vault_push` — mirroring the
`env_*` tools, with `vault_delete` and `vault_push` gated by the on-screen confirmation and
`--yes` unavailable to them.

There is no `vault_set` beside `vault_request_secret`, and the omission is structural rather than
cautious: `env_set` exists because a public key's value may legitimately come from the caller, and
no vault entry is public. Requesting a secret is the only way to create one from any surface.

`vault edit` and `vault init` are **CLI-only**, recorded in the parity table beside `classify
--set`, `hook`, and `mcp`. An agent quietly extending a credential's TTL is exactly the operation
that surface should not offer, and `init` chooses how the vault is protected at rest — the same
class of decision as `hook` editing the harness's own permission config.

### Error handling

- **No vault yet.** Reads treat it as empty: `list` prints nothing and exits 0, `has` exits 1.
  `push` and `rm` exit 3, naming the command that creates one.
- **File exists, keyring has no master key** — a backup restored onto a new machine, or a wiped
  keychain. Unrecoverable. Warden says so, exits 3, and names both options: restore the keychain
  item, or delete the vault file. It must **never** generate a fresh key and reseal, which would
  present data loss as success.
- **GCM authentication fails** — tampering or a wrong key. Same refusal, nothing rewritten.
  Warden never half-parses a vault.
- **Header says `keyring`, no keyring on this machine.** Clear message, exit 3, rather than
  falling back to a passphrase that cannot derive the right key.
- **Unknown version, bad base64, truncated file.** Refuse and leave it alone — the stance `hook
  --install` already takes toward an unparseable `settings.json`.
- **No prompt channel.** `ErrUnavailable`, exit 3, print the command to run by hand. Unchanged.

Because the whole file reseals on every write, two warden processes writing at once — a terminal
and an agent — could drop an entry. Writes take an `O_EXCL` lockfile at `~/.warden/vault.lock`
with a short stale timeout. Warden also re-asserts mode `0600` on every write, and reports when
it found the file more permissive.

### Scope

Deliberately out, and recorded here so the boundary is a decision rather than an oversight:

- **No `missing` / `doctor` integration.** `warden missing` will not mark which absent keys the
  vault could satisfy. The vault stays self-contained in this pass.
- **No `run --with-vault`.** `run` is itself unbuilt.
- **No sync, no sharing, no team vault.** One machine, one user.

## Testing

The four existing mechanisms grow rather than get bypassed:

- **Canary suite** — every `vault` subcommand gains a coverage-table row; registering one without
  it already fails the build. The fixture vault is built through the fake keyring with
  unique-marker values.
- **Parity test** — gains the vault CLI↔MCP mapping, with `vault edit` and `vault init` recorded
  as deliberate omissions.
- **Architecture test** — `internal/vault` and `internal/keyring` both join `internal/store` on
  the forbidden-import list for `internal/cli`, `internal/mcpserver`, and `cmd/warden`. The vault
  holds values; the keyring holds the key that unseals them. A surface package needs neither.
- **`Expose()` budget** — rises from 6 to 10, each new site named in the comment: sealing entry
  values, deriving the passphrase key, decoding the master key, each keyring backend's write, and
  handing a value to `store.Set` on push. The number goes up because the safe zone got bigger, and
  should be reviewed as such.

**The first test to write**, because this design contains a trap: `secret.Secret.MarshalJSON`
renders `<redacted>`. A vault that serializes entries naively writes the literal string
`<redacted>` into the sealed file as the credential — and it looks like it worked right up until
`push` hands a project the redaction marker. So the first test is a full round trip: `set` a
marker value, reseal, reopen, `push` into a fixture `.env`, assert the destination contains the
marker. That test failing is the difference between a vault and a shredder.

Then:

- Seal/open round trip. A flipped byte and a wrong key each fail authentication with nothing
  rewritten. Unknown version and truncated file refused.
- TTL against an injected clock: expired invisible to `has`, `list`, and `push`; purged at the
  next write; permanent entries untouched.
- `--ttl 30d` accepted and `--ttl 31d` refused with nothing written, on both `set` and `edit`. A
  clamping bug would pass a test that only checks the refusal message, so the assertion is on the
  stored deadline.
- `push` refuses an already-set destination key without `--force`, honours `--as`, requires
  confirmation; `--yes` works from the CLI and is absent from MCP.
- A cancelled prompt writes nothing and exits 3.
- Two concurrent writers do not drop an entry.
- `--global` refused on every vault subcommand.
- A vault built by `init --passphrase` round-trips through the Argon2id path with the fake prompt,
  and a keyring-built vault is unaffected by a passphrase being available. Both modes are exercised
  by the same round-trip assertions, since the mode is the header's business and no command above
  the format should be able to tell which one it is talking to.
