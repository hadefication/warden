# Warden Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `warden vault` — an encrypted, warden-owned store where a credential lives once, permanently or with a deadline, and from which it can be pushed into any project's `.env` without ever being rendered or retyped.

**Architecture:** Two new packages. `internal/keyring` wraps the OS keyring behind a three-method interface with a runner seam, so the master key never reaches argv. `internal/vault` owns the sealed file format (AES-256-GCM over a JSON document), entry metadata, and TTL. Surface packages reach the vault only through `internal/query` (reads) and `internal/write` (writes), exactly as they already reach `.env` — the existing architecture test is extended to enforce that.

**Tech Stack:** Go 1.26.4, `crypto/aes` + `crypto/cipher` (stdlib), `golang.org/x/crypto/argon2` (new dependency), `github.com/spf13/cobra`, `github.com/modelcontextprotocol/go-sdk`.

**Spec:** `docs/superpowers/specs/2026-08-18-warden-vault.md`

## Global Constraints

Every task's requirements implicitly include these. Values are copied verbatim from the spec.

- **Vault path:** `~/.warden/vault`, mode `0600`. Lockfile `~/.warden/vault.lock`.
- **Header line:** `warden-vault v1 <kdf> <base64 32-byte salt, or "-">` where `<kdf>` is `keyring` or `argon2id`. Header sits outside the seal; everything else is inside it, entry names included.
- **Keyring item:** service `warden`, account `vault-master`. The master key is 32 bytes from `crypto/rand`, stored base64.
- **Max TTL is 30 days (`720h`), refused rather than clamped.** Exceeding it exits 3 and names both alternatives: drop `--ttl` for permanent, or choose a window inside the cap.
- **An entry with no TTL is permanent and unbounded.** That asymmetry is deliberate.
- **Expired is indistinguishable from never-existed:** `has` exits 1, `list` omits it, `push` fails as absent. Purged at the next reseal.
- **Name charset:** `[A-Za-z0-9._-]+` segments joined by `/`, no leading/trailing `/`, no empty segment.
- **Env key shape:** `[A-Z_][A-Z0-9_]*`. `--key` may be omitted only when the entry name is itself a valid env key.
- **No read path.** There is no `vault get`. Exit code `2` never fires in the vault.
- **`--global` is refused on every vault subcommand**, never ignored.
- **`--yes` is CLI-only.** It must be unreachable from the MCP server.
- **`vault init` and `vault edit` are CLI-only.** No MCP tool for either.
- **`Expose()` budget rises from 6 to 10** in `internal/cli/arch_test.go`, and the comment names each new site.
- **No test may touch the real OS keyring or the real `$HOME`.** Use `keyring.Fake` and `t.TempDir()`.
- **CGO stays disabled.** No dependency may require cgo; keyring access is by shelling out.

---

## File Structure

**New packages:**

| File | Responsibility |
|---|---|
| `internal/keyring/keyring.go` | `Keyring` interface, `Fake`, `Unavailable`, `Default()`, the `runner` seam |
| `internal/keyring/security.go` | macOS backend over `/usr/bin/security` |
| `internal/keyring/secrettool.go` | Linux backend over `secret-tool` |
| `internal/vault/entry.go` | `Entry`, name/key validation, TTL rules, expiry predicates |
| `internal/vault/format.go` | header parse/render, seal/open, the wire type that defeats `Secret` redaction |
| `internal/vault/vault.go` | `Open`/`Init`/`Save`, master-key resolution, atomic write, lockfile |
| `internal/query/vault.go` | read surface: `OpenVault`, `List`, `Has` |
| `internal/write/vault.go` | write surface: `Init`, `Set`, `Edit`, `Remove`, `Push` |
| `internal/cli/vault.go` | the `vault` command family |

**Modified:**

| File | Change |
|---|---|
| `internal/write/write.go` | add unexported `setFromVault` so `Push` can reach the destination store |
| `internal/mcpserver/server.go` | five `vault_*` tools; extend `ToolNames()` |
| `internal/cli/cli.go` | call `addVaultCommands(root, out)` |
| `internal/cli/arch_test.go` | forbid `internal/vault` and `internal/keyring`; raise Expose budget to 10 |
| `internal/cli/parity_test.go` | walk subcommands one level deep; add vault rows |
| `internal/cli/canary_test.go` | vault rows in the coverage table; walk subcommands |
| `README.md` | vault section |
| `docs/superpowers/specs/2026-08-18-warden-vault.md` | status → implemented |

---

## Task 1: `internal/keyring` — the OS keyring behind a seam

**Files:**
- Create: `internal/keyring/keyring.go`
- Create: `internal/keyring/security.go`
- Create: `internal/keyring/secrettool.go`
- Test: `internal/keyring/keyring_test.go`

**Interfaces:**
- Consumes: `internal/secret` (`secret.Secret`).
- Produces: `keyring.Keyring` interface with `Get() (secret.Secret, error)`, `Set(secret.Secret) error`, `Delete() error`; `keyring.ErrNotFound`, `keyring.ErrUnavailable`; `keyring.Fake{Value secret.Secret, Present bool, GetErr, SetErr error, Deleted bool}`; `keyring.Security{Run runner}`, `keyring.SecretTool{Run runner}`, `keyring.Unavailable{}`, `keyring.Default() Keyring`; `type Runner func(name, stdin string, args ...string) ([]byte, error)`.

**Why the shape:** warden stores exactly one item, so the interface takes no service/account arguments — the constants are internal. The `Runner` seam exists so tests assert the exact argv without a keychain, and the single most important assertion in this task is that the master key appears **only in stdin, never in argv**, because argv is world-readable via `ps`.

- [ ] **Step 1: Write the failing tests**

Create `internal/keyring/keyring_test.go`:

```go
package keyring

import (
	"errors"
	"strings"
	"testing"

	"github.com/hadefication/warden/internal/secret"
)

// recorder captures what a backend would have executed.
type recorder struct {
	name  string
	args  []string
	stdin string
	out   []byte
	err   error
}

func (r *recorder) run(name, stdin string, args ...string) ([]byte, error) {
	r.name, r.stdin, r.args = name, stdin, args
	return r.out, r.err
}

// The master key must never reach argv: ps is world-readable. This is the
// reason the Runner seam exists at all.
func TestSecuritySetPassesTheValueOnStdinAndNeverInArgv(t *testing.T) {
	r := &recorder{}
	k := Security{Run: r.run}

	if err := k.Set(secret.Secret("master-key-marker")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, a := range r.args {
		if strings.Contains(a, "master-key-marker") {
			t.Fatalf("LEAK: the master key appeared in argv: %v", r.args)
		}
	}
	// security asks twice; a single line leaves the retype reading EOF and the
	// item is silently created empty.
	if r.stdin != "master-key-marker\nmaster-key-marker\n" {
		t.Errorf("stdin = %q, want the value twice", r.stdin)
	}
	if r.name != "security" {
		t.Errorf("name = %q, want security", r.name)
	}
	want := []string{"add-generic-password", "-s", "warden", "-a", "vault-master", "-U", "-w"}
	if strings.Join(r.args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", r.args, want)
	}
}

func TestSecurityGetTrimsTheTrailingNewline(t *testing.T) {
	r := &recorder{out: []byte("master-key-marker\n")}
	got, err := Security{Run: r.run}.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expose() != "master-key-marker" {
		t.Errorf("Get = %q, want the value without its newline", got.Expose())
	}
}

func TestSecurityGetReportsNotFound(t *testing.T) {
	r := &recorder{err: errors.New("exit status 44")}
	if _, err := (Security{Run: r.run}).Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestSecretToolSetPassesTheValueOnStdinOnce(t *testing.T) {
	r := &recorder{}
	if err := (SecretTool{Run: r.run}).Set(secret.Secret("master-key-marker")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, a := range r.args {
		if strings.Contains(a, "master-key-marker") {
			t.Fatalf("LEAK: the master key appeared in argv: %v", r.args)
		}
	}
	// secret-tool store reads the secret from stdin exactly once.
	if r.stdin != "master-key-marker" {
		t.Errorf("stdin = %q, want the value once with no newline", r.stdin)
	}
	want := []string{"store", "--label=warden", "service", "warden", "account", "vault-master"}
	if strings.Join(r.args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %v, want %v", r.args, want)
	}
}

func TestSecretToolGetTreatsEmptyOutputAsNotFound(t *testing.T) {
	r := &recorder{out: []byte("")}
	if _, err := (SecretTool{Run: r.run}).Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get error = %v, want ErrNotFound", err)
	}
}

func TestUnavailableRefusesEverything(t *testing.T) {
	u := Unavailable{}
	if _, err := u.Get(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Get error = %v, want ErrUnavailable", err)
	}
	if err := u.Set(secret.Secret("x")); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Set error = %v, want ErrUnavailable", err)
	}
	if err := u.Delete(); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Delete error = %v, want ErrUnavailable", err)
	}
}

func TestFakeRoundTrips(t *testing.T) {
	f := &Fake{}
	if _, err := f.Get(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Fake Get = %v, want ErrNotFound", err)
	}
	if err := f.Set(secret.Secret("k")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := f.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Expose() != "k" {
		t.Errorf("Get = %q, want k", got.Expose())
	}
	if err := f.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !f.Deleted {
		t.Error("Deleted flag not set")
	}
	if _, err := f.Get(); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// A Secret must not render its contents even when a backend errors.
func TestErrorsNeverQuoteTheValue(t *testing.T) {
	r := &recorder{err: errors.New("exit status 1")}
	err := Security{Run: r.run}.Set(secret.Secret("master-key-marker"))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "master-key-marker") {
		t.Errorf("LEAK: error quoted the value: %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/keyring/ -v`
Expected: FAIL — the package does not exist (`no Go files in .../internal/keyring`).

- [ ] **Step 3: Write `internal/keyring/keyring.go`**

```go
// Package keyring stores warden's vault master key in the operating system's
// keyring.
//
// Warden holds exactly one item, so the interface takes no service or account
// arguments — the constants below are the whole address space.
//
// Both backends shell out, because .goreleaser.yaml sets CGO_ENABLED=0 and that
// is what lets the installer drop one static file onto a machine with no
// toolchain. The consequence is written down in the vault spec: a keychain ACL
// protects /usr/bin/security rather than warden, so any process that can run
// security can read this key. Encryption at rest defends a synced backup, a
// stolen laptop and a cat of the file — not a local process.
package keyring

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hadefication/warden/internal/secret"
)

// The item's address in the OS keyring.
const (
	service = "warden"
	account = "vault-master"
)

var (
	// ErrNotFound means the keyring holds no item for warden.
	ErrNotFound = errors.New("no vault master key in the keyring")
	// ErrUnavailable means this machine offers no keyring to use.
	ErrUnavailable = errors.New("no OS keyring available")
)

// Keyring holds the vault's master key.
type Keyring interface {
	// Get returns the stored key, or ErrNotFound.
	Get() (secret.Secret, error)
	// Set stores the key, replacing any existing one.
	Set(v secret.Secret) error
	// Delete removes the item. Removing an absent item is not an error.
	Delete() error
}

// Runner executes a backend command. It is the seam tests replace: the master
// key must reach the child on stdin and never through args, because argv is
// world-readable via ps.
type Runner func(name, stdin string, args ...string) ([]byte, error)

// execRun is the production Runner. stderr is discarded deliberately: security
// writes "password data for new item:" prompts there even when piped, and that
// is noise rather than diagnosis.
func execRun(name, stdin string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.Output()
}

// Default picks the backend for this machine, or Unavailable when there is none.
func Default() Keyring {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return Security{Run: execRun}
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil {
			return SecretTool{Run: execRun}
		}
	}
	return Unavailable{}
}

// Unavailable is the backend for a machine with no keyring. Every method
// refuses, which is what sends the vault down its passphrase path.
type Unavailable struct{}

func (Unavailable) Get() (secret.Secret, error) { return "", ErrUnavailable }
func (Unavailable) Set(secret.Secret) error     { return ErrUnavailable }
func (Unavailable) Delete() error               { return ErrUnavailable }

// Fake is a test double. No test may touch a real keyring.
type Fake struct {
	Value   secret.Secret
	Present bool
	GetErr  error
	SetErr  error
	Deleted bool
}

func (f *Fake) Get() (secret.Secret, error) {
	if f.GetErr != nil {
		return "", f.GetErr
	}
	if !f.Present {
		return "", ErrNotFound
	}
	return f.Value, nil
}

func (f *Fake) Set(v secret.Secret) error {
	if f.SetErr != nil {
		return f.SetErr
	}
	f.Value, f.Present = v, true
	return nil
}

func (f *Fake) Delete() error {
	f.Value, f.Present, f.Deleted = "", false, true
	return nil
}

// wrapErr reports a backend failure without ever quoting the value. The caller
// is frequently an agent, and a failed write is not a reason to disclose a key.
func wrapErr(op string, err error) error {
	return fmt.Errorf("keyring %s failed: %w", op, err)
}
```

- [ ] **Step 4: Write `internal/keyring/security.go`**

```go
package keyring

import (
	"strings"

	"github.com/hadefication/warden/internal/secret"
)

// Security is the macOS backend, over /usr/bin/security.
type Security struct{ Run Runner }

// Get reads the item. -w prints only the password, with a trailing newline.
func (s Security) Get() (secret.Secret, error) {
	out, err := s.Run("security", "",
		"find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		// security exits non-zero for "item not found" and for a locked
		// keychain alike. Both mean the same thing to a caller: no key here.
		return "", ErrNotFound
	}
	return secret.Secret(strings.TrimRight(string(out), "\r\n")), nil
}

// Set writes the item, replacing any existing one.
//
// -w is passed last and with no value, which makes security read the password
// from stdin rather than argv. It asks twice — once to enter and once to retype
// — so the value is piped twice. A single line leaves the retype reading EOF,
// which security reports as "passwords don't match" and then creates the item
// with an empty password: a silent, total data loss.
func (s Security) Set(v secret.Secret) error {
	stdin := v.Expose() + "\n" + v.Expose() + "\n"
	if _, err := s.Run("security", stdin,
		"add-generic-password", "-s", service, "-a", account, "-U", "-w"); err != nil {
		return wrapErr("write", err)
	}
	return nil
}

// Delete removes the item. An absent item is not an error.
func (s Security) Delete() error {
	_, _ = s.Run("security", "", "delete-generic-password", "-s", service, "-a", account)
	return nil
}
```

- [ ] **Step 5: Write `internal/keyring/secrettool.go`**

```go
package keyring

import (
	"github.com/hadefication/warden/internal/secret"
)

// SecretTool is the Linux backend, over libsecret's secret-tool.
type SecretTool struct{ Run Runner }

// Get reads the item. secret-tool lookup prints the secret with no trailing
// newline, and prints nothing at all when there is no match.
func (s SecretTool) Get() (secret.Secret, error) {
	out, err := s.Run("secret-tool", "", "lookup", "service", service, "account", account)
	if err != nil || len(out) == 0 {
		return "", ErrNotFound
	}
	return secret.Secret(out), nil
}

// Set writes the item. secret-tool store reads the secret from stdin exactly
// once — unlike security, it does not ask for a retype.
func (s SecretTool) Set(v secret.Secret) error {
	if _, err := s.Run("secret-tool", v.Expose(),
		"store", "--label="+service, "service", service, "account", account); err != nil {
		return wrapErr("write", err)
	}
	return nil
}

// Delete removes the item. An absent item is not an error.
func (s SecretTool) Delete() error {
	_, _ = s.Run("secret-tool", "", "clear", "service", service, "account", account)
	return nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/keyring/ -v`
Expected: PASS, all nine tests.

- [ ] **Step 7: Confirm nothing else broke and vet is clean**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all packages PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/keyring
git commit -m "feat(keyring): store the vault master key in the OS keyring

Two backends behind one interface, both shelling out because CGO_ENABLED=0
is what makes the release binaries static. The Runner seam exists so tests
can assert the property that matters: the master key reaches the child on
stdin and never through argv, which ps would expose.

security needs the value piped twice. Passing -w last makes it read stdin,
but it asks for a retype, and a single line leaves that read hitting EOF —
security then reports a mismatch and creates the item with an empty
password, which would be silent total data loss."
```

---

## Task 2: `internal/vault` — the sealed file format

**Files:**
- Create: `internal/vault/entry.go`
- Create: `internal/vault/format.go`
- Test: `internal/vault/format_test.go`

**Interfaces:**
- Consumes: `internal/secret`.
- Produces: `vault.Entry{Name, Key string, Value secret.Secret, Created, Expires time.Time}` with methods `Permanent() bool` and `ExpiredAt(now time.Time) bool`; `vault.Mode` (`ModeKeyring`, `ModeArgon2id`); `vault.MaxTTL`; `vault.ValidateName(string) error`, `vault.ValidateKey(string) error`, `vault.ValidateTTL(time.Duration) error`; errors `ErrBadName`, `ErrBadKey`, `ErrTTLTooLong`, `ErrBadFormat`, `ErrUndecryptable`; and the unexported `header`, `parseHeader`, `renderHeader`, `sealDoc`, `openDoc` used by Task 3.

**Why this task is separate:** the format is the one place a bug is unrecoverable — a vault written wrong cannot be read back, and the failure is invisible until a push hands a project the wrong bytes. It gets its own test cycle and its own review gate before any command can reach it.

**The trap, stated once:** `secret.Secret.MarshalJSON` renders `<redacted>`. A vault that serializes `Entry` directly writes the literal string `<redacted>` into the sealed file as the credential, and it looks like it worked right up until `push`. `format.go` therefore converts to an unexported wire type that carries a plain `string`, and the first test asserts a round trip on a marker value.

- [ ] **Step 1: Write the failing tests**

Create `internal/vault/format_test.go`:

```go
package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/secret"
)

func testKey() []byte { return bytes.Repeat([]byte{7}, 32) }

// THE test for this package. secret.Secret.MarshalJSON renders "<redacted>", so
// a naive encode writes the redaction marker into the vault as the credential —
// and nothing looks wrong until a push hands a project that string. A vault that
// cannot return what it stored is a shredder.
func TestSealedDocumentRoundTripsTheRealValueAndNotTheRedactionMarker(t *testing.T) {
	const marker = "vault-marker-9f2c14ab"
	created := time.Date(2026, 8, 18, 10, 4, 0, 0, time.UTC)
	in := []Entry{{
		Name:    "stripe/live",
		Key:     "STRIPE_SECRET",
		Value:   secret.Secret(marker),
		Created: created,
	}}

	blob, err := sealDoc(testKey(), in)
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	if bytes.Contains(blob, []byte(marker)) {
		t.Fatal("the sealed blob contains the plaintext value — it is not encrypted")
	}
	if bytes.Contains(blob, []byte(secret.Redacted)) {
		t.Fatal("the sealed blob contains the redaction marker in the clear")
	}

	out, err := openDoc(testKey(), blob)
	if err != nil {
		t.Fatalf("openDoc: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d entries, want 1", len(out))
	}
	if got := out[0].Value.Expose(); got != marker {
		t.Fatalf("value round-tripped as %q, want %q — the redaction marker was stored instead of the value",
			got, marker)
	}
	if out[0].Name != "stripe/live" || out[0].Key != "STRIPE_SECRET" {
		t.Errorf("metadata round-tripped as %q/%q", out[0].Name, out[0].Key)
	}
	if !out[0].Created.Equal(created) {
		t.Errorf("created = %v, want %v", out[0].Created, created)
	}
	if !out[0].Permanent() {
		t.Error("an entry with no deadline should be permanent")
	}
}

// Entry names are inside the seal because a name is itself worth not leaking.
func TestSealedDocumentHidesEntryNames(t *testing.T) {
	blob, err := sealDoc(testKey(), []Entry{{
		Name: "acme/prod-db", Key: "DB_PASSWORD", Value: secret.Secret("v"),
	}})
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	if bytes.Contains(blob, []byte("acme/prod-db")) {
		t.Error("the entry name is readable in the sealed blob")
	}
}

func TestExpiryRoundTrips(t *testing.T) {
	deadline := time.Date(2026, 8, 18, 18, 4, 0, 0, time.UTC)
	blob, err := sealDoc(testKey(), []Entry{{
		Name: "tmp", Key: "TMP_TOKEN", Value: secret.Secret("v"), Expires: deadline,
	}})
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	out, err := openDoc(testKey(), blob)
	if err != nil {
		t.Fatalf("openDoc: %v", err)
	}
	if out[0].Permanent() {
		t.Fatal("an entry with a deadline is not permanent")
	}
	if !out[0].Expires.Equal(deadline) {
		t.Errorf("expires = %v, want %v", out[0].Expires, deadline)
	}
}

func TestAFlippedByteFailsAuthentication(t *testing.T) {
	blob, err := sealDoc(testKey(), []Entry{{Name: "a", Key: "A", Value: secret.Secret("v")}})
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	blob[len(blob)-1] ^= 0x01
	if _, err := openDoc(testKey(), blob); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("openDoc on tampered blob = %v, want ErrUndecryptable", err)
	}
}

func TestTheWrongKeyFailsAuthentication(t *testing.T) {
	blob, err := sealDoc(testKey(), []Entry{{Name: "a", Key: "A", Value: secret.Secret("v")}})
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	wrong := bytes.Repeat([]byte{9}, 32)
	if _, err := openDoc(wrong, blob); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("openDoc with wrong key = %v, want ErrUndecryptable", err)
	}
}

func TestATruncatedBlobIsRefused(t *testing.T) {
	if _, err := openDoc(testKey(), []byte{1, 2, 3}); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("openDoc on a short blob = %v, want ErrUndecryptable", err)
	}
}

// Two seals of the same entries must differ: a fresh nonce each time.
func TestSealUsesAFreshNonce(t *testing.T) {
	e := []Entry{{Name: "a", Key: "A", Value: secret.Secret("v")}}
	one, err := sealDoc(testKey(), e)
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	two, err := sealDoc(testKey(), e)
	if err != nil {
		t.Fatalf("sealDoc: %v", err)
	}
	if bytes.Equal(one, two) {
		t.Error("two seals are byte-identical — the nonce is not fresh")
	}
}

func TestHeaderRoundTripsKeyringMode(t *testing.T) {
	line := renderHeader(header{Mode: ModeKeyring})
	if line != "warden-vault v1 keyring -" {
		t.Fatalf("rendered %q", line)
	}
	h, err := parseHeader(line)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.Mode != ModeKeyring || len(h.Salt) != 0 {
		t.Errorf("parsed %+v, want keyring mode with no salt", h)
	}
}

func TestHeaderRoundTripsArgon2idModeWithSalt(t *testing.T) {
	salt := bytes.Repeat([]byte{3}, 32)
	h, err := parseHeader(renderHeader(header{Mode: ModeArgon2id, Salt: salt}))
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	if h.Mode != ModeArgon2id {
		t.Errorf("mode = %q, want argon2id", h.Mode)
	}
	if !bytes.Equal(h.Salt, salt) {
		t.Error("salt did not round-trip")
	}
}

func TestUnknownVersionIsRefused(t *testing.T) {
	if _, err := parseHeader("warden-vault v2 keyring -"); !errors.Is(err, ErrBadFormat) {
		t.Errorf("parseHeader v2 = %v, want ErrBadFormat", err)
	}
}

func TestGarbageHeaderIsRefused(t *testing.T) {
	for _, line := range []string{
		"", "not-a-vault", "warden-vault", "warden-vault v1",
		"warden-vault v1 rot13 -", "warden-vault v1 argon2id !!!notbase64",
	} {
		if _, err := parseHeader(line); !errors.Is(err, ErrBadFormat) {
			t.Errorf("parseHeader(%q) = %v, want ErrBadFormat", line, err)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"STRIPE_SECRET", "stripe/live", "a", "a.b-c_d", "x/y/z"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "/leading", "trailing/", "double//slash", "has space",
		"new\nline", "quote\"d", "semi;colon", "..", "a/../b",
	} {
		if err := ValidateName(bad); !errors.Is(err, ErrBadName) {
			t.Errorf("ValidateName(%q) = %v, want ErrBadName", bad, err)
		}
	}
}

func TestValidateKey(t *testing.T) {
	for _, ok := range []string{"A", "STRIPE_SECRET", "_X", "A1_B2"} {
		if err := ValidateKey(ok); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "lower", "1LEADING", "has space", "WITH-DASH", "a/b"} {
		if err := ValidateKey(bad); !errors.Is(err, ErrBadKey) {
			t.Errorf("ValidateKey(%q) = %v, want ErrBadKey", bad, err)
		}
	}
}

// The cap refuses rather than clamps: silently shortening a window would have
// the user believe a credential lives for a year while it dies in a month.
func TestValidateTTLRefusesBeyondThirtyDaysAndNeverClamps(t *testing.T) {
	if err := ValidateTTL(MaxTTL); err != nil {
		t.Errorf("ValidateTTL(30d) = %v, want nil — the cap is inclusive", err)
	}
	if err := ValidateTTL(MaxTTL + time.Second); !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("ValidateTTL(30d+1s) = %v, want ErrTTLTooLong", err)
	}
	if err := ValidateTTL(31 * 24 * time.Hour); !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("ValidateTTL(31d) = %v, want ErrTTLTooLong", err)
	}
	if err := ValidateTTL(0); err != nil {
		t.Errorf("ValidateTTL(0) = %v, want nil — zero means permanent", err)
	}
	if err := ValidateTTL(-time.Hour); !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("ValidateTTL(negative) = %v, want a refusal", err)
	}
}

// The message has to name both honest alternatives, or a user hitting the cap
// has no idea what to do instead.
func TestTTLRefusalNamesBothAlternatives(t *testing.T) {
	err := ValidateTTL(365 * 24 * time.Hour)
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--ttl") || !strings.Contains(msg, "permanent") {
		t.Errorf("message %q should name dropping --ttl for a permanent entry", msg)
	}
}

func TestExpiredAt(t *testing.T) {
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	perm := Entry{Name: "p"}
	if perm.ExpiredAt(now) {
		t.Error("a permanent entry never expires")
	}
	future := Entry{Name: "f", Expires: now.Add(time.Hour)}
	if future.ExpiredAt(now) {
		t.Error("an entry with a future deadline is live")
	}
	past := Entry{Name: "x", Expires: now.Add(-time.Second)}
	if !past.ExpiredAt(now) {
		t.Error("an entry one second past its deadline is expired")
	}
	// The boundary belongs to the past: at exactly the deadline it is gone.
	at := Entry{Name: "b", Expires: now}
	if !at.ExpiredAt(now) {
		t.Error("an entry exactly at its deadline is expired")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/vault/ -v`
Expected: FAIL — no Go files in `internal/vault`.

- [ ] **Step 3: Write `internal/vault/entry.go`**

```go
// Package vault stores credentials warden owns, rather than credentials a
// project's .env happens to hold.
//
// Every value leaves this package as a secret.Secret. internal/cli,
// internal/mcpserver and cmd/warden are forbidden from importing it —
// internal/cli/arch_test.go enforces that — so a surface reaches the vault only
// through internal/query and internal/write, exactly as it reaches a .env.
package vault

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/hadefication/warden/internal/secret"
)

// MaxTTL caps a temporary entry at 30 days.
//
// The cap's job is to stop --ttl 8760h being used as a permanent entry that
// quietly dies. An entry with no TTL is unbounded, and that asymmetry is the
// point: absent means "this lives here until I remove it", stated plainly. A
// large number pretending to mean the same thing is the failure mode.
const MaxTTL = 30 * 24 * time.Hour

// Mode is how the file's master key is derived.
type Mode string

const (
	// ModeKeyring takes the key from the OS keyring. The default.
	ModeKeyring Mode = "keyring"
	// ModeArgon2id derives it from a passphrase.
	ModeArgon2id Mode = "argon2id"
)

var (
	// ErrBadName means an entry name is not a legal name.
	ErrBadName = errors.New("invalid entry name")
	// ErrBadKey means a target env key is not a legal env key.
	ErrBadKey = errors.New("invalid env key")
	// ErrTTLTooLong means a requested window exceeds MaxTTL.
	ErrTTLTooLong = errors.New("ttl exceeds the maximum")
	// ErrBadFormat means the file is not a vault this build understands.
	ErrBadFormat = errors.New("not a readable warden vault")
	// ErrUndecryptable means the blob failed authentication: tampering, or the
	// wrong key. Warden never half-parses a vault.
	ErrUndecryptable = errors.New("vault could not be decrypted")
)

// Entry is one stored credential.
//
// Name is how it is addressed; Key is the env key it lands as. The indirection
// is what lets two projects with different DB_PASSWORD values coexist, which a
// store addressed by env key cannot do.
type Entry struct {
	Name    string
	Key     string
	Value   secret.Secret
	Created time.Time
	// Expires is the absolute deadline. The zero time means permanent.
	Expires time.Time
}

// Permanent reports whether the entry has no deadline.
func (e Entry) Permanent() bool { return e.Expires.IsZero() }

// ExpiredAt reports whether the entry is past its deadline at now. The boundary
// belongs to the past: at exactly the deadline, the entry is gone.
func (e Entry) ExpiredAt(now time.Time) bool {
	return !e.Permanent() && !now.Before(e.Expires)
}

// A name is dot, dash, underscore and alphanumeric segments joined by slashes.
// Names are keys in a JSON document rather than paths on disk, but a name
// carrying a newline would corrupt list output, so the charset is validated on
// the way in.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)

// envKeyRE is the shape of an environment variable name.
var envKeyRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ValidateName accepts a legal entry name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf(
			"%q: %w — use letters, digits, dot, dash and underscore, in segments joined by /",
			name, ErrBadName)
	}
	// "." and ".." are legal under the charset but read as path traversal to
	// every human who sees them, and a name is not a path. Refuse both.
	for _, seg := range splitSegments(name) {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%q: %w — %q is not a usable segment", name, ErrBadName, seg)
		}
	}
	return nil
}

// ValidateKey accepts a legal environment variable name.
func ValidateKey(key string) error {
	if !envKeyRE.MatchString(key) {
		return fmt.Errorf("%q: %w — env keys are upper case, digits and underscore", key, ErrBadKey)
	}
	return nil
}

// LooksLikeEnvKey reports whether a name may double as its own env key, which is
// what lets `warden vault set STRIPE_SECRET` omit --key.
func LooksLikeEnvKey(name string) bool { return envKeyRE.MatchString(name) }

// ValidateTTL accepts zero (permanent) or a window inside MaxTTL.
//
// It refuses rather than clamps. Silently shortening a requested window is the
// worst option available: the user would believe a credential lives for a year
// while it dies in a month, which is precisely the surprise the cap exists to
// prevent.
func ValidateTTL(d time.Duration) error {
	if d == 0 {
		return nil
	}
	if d < 0 {
		return fmt.Errorf("%w: a negative window is not a deadline", ErrTTLTooLong)
	}
	if d > MaxTTL {
		return fmt.Errorf(
			"%w: %s is longer than the 30d maximum — either drop --ttl for a permanent entry, "+
				"or choose a window inside the cap",
			ErrTTLTooLong, d)
	}
	return nil
}

func splitSegments(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '/' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return append(out, name[start:])
}
```

- [ ] **Step 4: Write `internal/vault/format.go`**

```go
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hadefication/warden/internal/secret"
)

const (
	headerMagic   = "warden-vault"
	headerVersion = "v1"
	// docVersion is the schema of the JSON document under the seal.
	docVersion = 1
	// saltLen and keyLen are both 32: a 256-bit salt and an AES-256 key.
	saltLen = 32
	keyLen  = 32
)

// header is the plaintext first line. It says how to unseal the file and
// nothing about what is inside — entry names included, which is why they are
// under the seal rather than beside it.
type header struct {
	Mode Mode
	Salt []byte // ModeArgon2id only
}

// renderHeader writes the header line. The salt field is "-" when unused rather
// than empty, so the line always has four fields and a truncated write is
// detectable.
func renderHeader(h header) string {
	salt := "-"
	if len(h.Salt) > 0 {
		salt = base64.StdEncoding.EncodeToString(h.Salt)
	}
	return fmt.Sprintf("%s %s %s %s", headerMagic, headerVersion, h.Mode, salt)
}

// parseHeader reads the header line, refusing anything it does not fully
// understand rather than guessing. A vault warden cannot read is left alone —
// the same stance hook --install takes toward an unparseable settings.json.
func parseHeader(line string) (header, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 4 || fields[0] != headerMagic {
		return header{}, fmt.Errorf("%w: unrecognised header", ErrBadFormat)
	}
	if fields[1] != headerVersion {
		return header{}, fmt.Errorf(
			"%w: this file is %s and this warden understands %s — upgrade warden rather than "+
				"letting it rewrite a vault it cannot read",
			ErrBadFormat, fields[1], headerVersion)
	}

	h := header{Mode: Mode(fields[2])}
	switch h.Mode {
	case ModeKeyring, ModeArgon2id:
	default:
		return header{}, fmt.Errorf("%w: unknown key mode %q", ErrBadFormat, fields[2])
	}

	if fields[3] != "-" {
		salt, err := base64.StdEncoding.DecodeString(fields[3])
		if err != nil {
			return header{}, fmt.Errorf("%w: the salt is not valid base64", ErrBadFormat)
		}
		h.Salt = salt
	}
	if h.Mode == ModeArgon2id && len(h.Salt) == 0 {
		return header{}, fmt.Errorf("%w: argon2id mode with no salt", ErrBadFormat)
	}
	return h, nil
}

// wireEntry is the on-disk shape of an Entry.
//
// It exists for one reason: secret.Secret.MarshalJSON renders "<redacted>", so
// encoding an Entry directly would write the redaction marker into the vault as
// the credential — and nothing would look wrong until a push handed a project
// that string. The conversion below is the single place a vault value is
// exposed, and format_test.go asserts the round trip on a marker value.
type wireEntry struct {
	Name    string     `json:"name"`
	Key     string     `json:"key"`
	Value   string     `json:"value"`
	Created time.Time  `json:"created"`
	Expires *time.Time `json:"expires,omitempty"`
}

type document struct {
	Version int         `json:"version"`
	Entries []wireEntry `json:"entries"`
}

// sealDoc encodes entries and seals them under key. The output is nonce
// followed by ciphertext.
func sealDoc(key []byte, entries []Entry) ([]byte, error) {
	doc := document{Version: docVersion, Entries: make([]wireEntry, 0, len(entries))}
	for _, e := range entries {
		w := wireEntry{
			Name:    e.Name,
			Key:     e.Key,
			Value:   e.Value.Expose(),
			Created: e.Created,
		}
		if !e.Permanent() {
			d := e.Expires
			w.Expires = &d
		}
		doc.Entries = append(doc.Entries, w)
	}

	plain, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encoding the vault: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating a nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// openDoc unseals a blob produced by sealDoc.
func openDoc(key, blob []byte) ([]Entry, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: the file is too short to contain a nonce", ErrUndecryptable)
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Authentication failure means tampering or the wrong key, and there is
		// no way to tell which. Neither is a reason to guess.
		return nil, fmt.Errorf(
			"%w: authentication failed — the file was modified, or the master key is not the one "+
				"it was sealed with", ErrUndecryptable)
	}

	var doc document
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, fmt.Errorf("%w: the decrypted contents are not a vault document", ErrBadFormat)
	}
	if doc.Version != docVersion {
		return nil, fmt.Errorf("%w: document version %d", ErrBadFormat, doc.Version)
	}

	entries := make([]Entry, 0, len(doc.Entries))
	for _, w := range doc.Entries {
		e := Entry{
			Name:    w.Name,
			Key:     w.Key,
			Value:   secret.Secret(w.Value),
			Created: w.Created,
		}
		if w.Expires != nil {
			e.Expires = *w.Expires
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("%w: the master key is %d bytes, want %d", ErrUndecryptable, len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUndecryptable, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUndecryptable, err)
	}
	return gcm, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/vault/ -v`
Expected: PASS. If `TestSealedDocumentRoundTripsTheRealValueAndNotTheRedactionMarker` fails with `value round-tripped as "<redacted>"`, the `wireEntry` conversion was skipped — that is the trap this task exists to close.

- [ ] **Step 6: Verify the whole suite and vet**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/vault
git commit -m "feat(vault): seal entries into one AES-256-GCM document

The header stays outside the seal because it says how to unseal the file and
nothing about what is inside; entry names go under it, since acme/prod-db is
itself worth not leaking.

wireEntry exists for one reason: secret.Secret.MarshalJSON renders
<redacted>, so encoding an Entry directly would write the redaction marker
into the vault as the credential — invisible until a push handed a project
that string. The round-trip test on a marker value is the first test here.

The TTL cap refuses rather than clamps. Silently shortening a window would
have the user believe a credential lives a year while it dies in a month."
```

---

## Task 3: `internal/vault` — open, save, and the master key

**Files:**
- Create: `internal/vault/vault.go`
- Test: `internal/vault/vault_test.go`
- Modify: `go.mod` / `go.sum` (add `golang.org/x/crypto`)

**Interfaces:**
- Consumes: `vault.Entry`, `vault.Mode`, `sealDoc`, `openDoc`, `parseHeader`, `renderHeader` (Task 2); `keyring.Keyring`, `keyring.ErrNotFound` (Task 1); `internal/prompt`.
- Produces: `vault.Options{Home string, Keyring keyring.Keyring, Prompt prompt.Prompter, Now func() time.Time}`; `vault.Path(home string) string`; `vault.Init(Options, Mode) error`; `vault.Open(Options) (*V, error)`; on `*V`: `Path() string`, `Mode() Mode`, `Exists() bool`, `Loosened() bool`, `List() []Entry`, `Get(name string) (Entry, bool)`, `Put(Entry) error`, `Remove(name string) bool`, `Rename(old, new string) error`, `Save() error`; errors `ErrNoVault`, `ErrNoMasterKey`, `ErrExists`, `ErrLocked`.

**Semantics fixed here:**
- `Open` on a missing file succeeds and yields an empty vault in `ModeKeyring` — reads treat "no vault" as "no entries", and only `Save` creates the file.
- `List` returns unexpired entries sorted by name. `Get` refuses an expired entry, so expired is indistinguishable from never-existed at the only door in.
- `Save` purges expired entries, seals, writes a temp file and renames, and re-asserts `0600`.
- **Never** generate a fresh master key when the file exists but the keyring has none. That would present total data loss as success.

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get golang.org/x/crypto@latest && go mod tidy
```
Expected: `golang.org/x/crypto` appears in `go.mod`'s require block. Confirm no cgo dependency crept in with `CGO_ENABLED=0 go build ./...`.

- [ ] **Step 2: Write the failing tests**

Create `internal/vault/vault_test.go`:

```go
package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/secret"
)

var testNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// opts builds Options against a temp home and a fake keyring. No test may touch
// the real keyring or the real $HOME.
func opts(t *testing.T) (Options, *keyring.Fake) {
	t.Helper()
	kr := &keyring.Fake{}
	return Options{
		Home:    t.TempDir(),
		Keyring: kr,
		Prompt:  prompt.Fake{Value: "test-passphrase"},
		Now:     func() time.Time { return testNow },
	}, kr
}

func TestOpenOnAMissingFileYieldsAnEmptyVault(t *testing.T) {
	o, _ := opts(t)
	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v — a missing vault is not an error on the read path", err)
	}
	if v.Exists() {
		t.Error("Exists should be false before anything is saved")
	}
	if len(v.List()) != 0 {
		t.Errorf("List = %v, want empty", v.List())
	}
	if _, err := os.Stat(v.Path()); !os.IsNotExist(err) {
		t.Error("Open must not create the file; only Save does")
	}
}

func TestPathIsUnderDotWarden(t *testing.T) {
	home := t.TempDir()
	if got, want := Path(home), filepath.Join(home, ".warden", "vault"); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
}

func TestSaveThenOpenRoundTripsThroughTheKeyring(t *testing.T) {
	const marker = "vault-marker-3d71fe02"
	o, kr := opts(t)

	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(Entry{Name: "stripe/live", Key: "STRIPE_SECRET", Value: secret.Secret(marker)}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if !kr.Present {
		t.Fatal("Save should have stored a master key in the keyring")
	}

	// The file must not contain the value in the clear.
	raw, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatal("the vault file contains the plaintext value")
	}
	if !strings.HasPrefix(string(raw), "warden-vault v1 keyring -") {
		t.Errorf("header line is %q", strings.SplitN(string(raw), "\n", 2)[0])
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get("stripe/live")
	if !ok {
		t.Fatal("the entry did not survive the round trip")
	}
	if got.Value.Expose() != marker {
		t.Errorf("value = %q, want %q", got.Value.Expose(), marker)
	}
	if got.Created.IsZero() {
		t.Error("Put should stamp Created from the injected clock")
	}
}

func TestSaveWritesModeSixHundred(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	if err := v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(v.Path())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
}

func TestSaveReassertsModeAndReportsThatItFoundItLoosened(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(v.Path(), 0o644); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.Loosened() {
		t.Error("Loosened should report a vault found more permissive than 0600")
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, _ := os.Stat(reopened.Path())
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode after save = %o, want 600", perm)
	}
}

// The single most destructive thing this package could do.
func TestAVaultWhoseKeyIsGoneIsRefusedAndNeverRekeyed(t *testing.T) {
	o, kr := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	before, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatal(err)
	}

	// The keychain item is gone: a restored backup, or a wiped keychain.
	kr.Present, kr.Value = false, ""

	_, err = Open(o)
	if !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("Open = %v, want ErrNoMasterKey", err)
	}
	// It must name both options rather than leaving the user stuck.
	if msg := err.Error(); !strings.Contains(msg, "keychain") || !strings.Contains(msg, "delete") {
		t.Errorf("message %q should name restoring the keychain item and deleting the vault", msg)
	}

	after, err := os.ReadFile(v.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the vault file was rewritten — a fresh key was generated and the data is gone")
	}
}

func TestArgon2idModeDerivesFromThePassphrase(t *testing.T) {
	const marker = "vault-marker-argon-7c31"
	o, kr := opts(t)

	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if kr.Present {
		t.Error("argon2id mode must not put anything in the keyring")
	}

	v, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if v.Mode() != ModeArgon2id {
		t.Fatalf("mode = %q, want argon2id", v.Mode())
	}
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret(marker)})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reopened, err := Open(o)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := reopened.Get("A")
	if !ok || got.Value.Expose() != marker {
		t.Errorf("argon2id round trip failed: ok=%v value=%q", ok, got.Value.Expose())
	}
}

func TestTheWrongPassphraseFailsAuthentication(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "A", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	wrong := o
	wrong.Prompt = prompt.Fake{Value: "not-the-passphrase"}
	if _, err := Open(wrong); !errors.Is(err, ErrUndecryptable) {
		t.Errorf("Open with the wrong passphrase = %v, want ErrUndecryptable", err)
	}
}

func TestACancelledPassphrasePromptWritesNothing(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeArgon2id); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cancelled := o
	cancelled.Prompt = prompt.Fake{Err: prompt.ErrCancelled}
	if _, err := Open(cancelled); !errors.Is(err, prompt.ErrCancelled) {
		t.Errorf("Open = %v, want ErrCancelled", err)
	}
}

func TestInitRefusesAnExistingVault(t *testing.T) {
	o, _ := opts(t)
	if err := Init(o, ModeKeyring); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := Init(o, ModeKeyring); !errors.Is(err, ErrExists) {
		t.Errorf("second Init = %v, want ErrExists", err)
	}
}

func TestPutValidatesNameKeyAndTTL(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)

	if err := v.Put(Entry{Name: "bad name", Key: "A", Value: secret.Secret("v")}); !errors.Is(err, ErrBadName) {
		t.Errorf("Put with a bad name = %v, want ErrBadName", err)
	}
	if err := v.Put(Entry{Name: "ok", Key: "lower", Value: secret.Secret("v")}); !errors.Is(err, ErrBadKey) {
		t.Errorf("Put with a bad key = %v, want ErrBadKey", err)
	}
	tooLong := Entry{
		Name: "ok", Key: "A", Value: secret.Secret("v"),
		Expires: testNow.Add(MaxTTL + time.Hour),
	}
	if err := v.Put(tooLong); !errors.Is(err, ErrTTLTooLong) {
		t.Errorf("Put beyond the cap = %v, want ErrTTLTooLong", err)
	}
}

func TestPutReplacesByName(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("first")})
	_ = v.Put(Entry{Name: "a", Key: "B", Value: secret.Secret("second")})

	if n := len(v.List()); n != 1 {
		t.Fatalf("got %d entries, want 1 — Put should replace by name", n)
	}
	got, _ := v.Get("a")
	if got.Value.Expose() != "second" || got.Key != "B" {
		t.Errorf("entry = %q/%q, want second/B", got.Value.Expose(), got.Key)
	}
}

// Two entries with the same target key is the whole reason names exist.
func TestTwoEntriesMayShareATargetKey(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	if err := v.Put(Entry{Name: "acme/db", Key: "DB_PASSWORD", Value: secret.Secret("one")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := v.Put(Entry{Name: "beta/db", Key: "DB_PASSWORD", Value: secret.Secret("two")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if n := len(v.List()); n != 2 {
		t.Fatalf("got %d entries, want 2", n)
	}
}

func TestListIsSortedByName(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	for _, n := range []string{"zeta", "alpha", "mid/one"} {
		_ = v.Put(Entry{Name: n, Key: "A", Value: secret.Secret("v")})
	}
	got := []string{v.List()[0].Name, v.List()[1].Name, v.List()[2].Name}
	want := []string{"alpha", "mid/one", "zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List order = %v, want %v", got, want)
		}
	}
}

func TestAnExpiredEntryIsInvisibleToListAndGet(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "live", Key: "A", Value: secret.Secret("v"), Expires: testNow.Add(time.Hour)})
	_ = v.Put(Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: testNow.Add(-time.Second)})

	if n := len(v.List()); n != 1 || v.List()[0].Name != "live" {
		t.Fatalf("List = %v, want only the live entry", v.List())
	}
	if _, ok := v.Get("dead"); ok {
		t.Error("Get returned an expired entry — expired must be indistinguishable from absent")
	}
}

func TestSavePurgesExpiredEntries(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "live", Key: "A", Value: secret.Secret("v")})
	// Put refuses a deadline beyond the cap but not one in the past: an entry
	// can expire while the process holds it.
	_ = v.Put(Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: testNow.Add(time.Minute)})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	later := o
	later.Now = func() time.Time { return testNow.Add(time.Hour) }
	reopened, err := Open(later)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A third open with the clock rolled back proves the entry is gone from the
	// file rather than merely filtered by the clock.
	back, err := Open(o)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	if _, ok := back.Get("dead"); ok {
		t.Error("the expired entry survived the reseal — Save must purge it")
	}
	if _, ok := back.Get("live"); !ok {
		t.Error("Save purged a permanent entry")
	}
}

func TestRemoveAndRename(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})

	if err := v.Rename("a", "b/c"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, ok := v.Get("a"); ok {
		t.Error("the old name still resolves")
	}
	if _, ok := v.Get("b/c"); !ok {
		t.Error("the new name does not resolve")
	}
	if err := v.Rename("nope", "x"); !errors.Is(err, ErrNoVault) {
		t.Errorf("Rename of an absent entry = %v, want ErrNoVault", err)
	}
	if err := v.Rename("b/c", "bad name"); !errors.Is(err, ErrBadName) {
		t.Errorf("Rename to an illegal name = %v, want ErrBadName", err)
	}

	if !v.Remove("b/c") {
		t.Error("Remove should report that it removed something")
	}
	if v.Remove("b/c") {
		t.Error("Remove of an absent entry should report false")
	}
}

// Two writers, one file. The whole document reseals on every write, so an
// unguarded second writer silently drops the first writer's entry.
func TestSaveIsSerialisedByALockfile(t *testing.T) {
	o, _ := opts(t)
	first, _ := Open(o)
	_ = first.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := first.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Hold the lock, then prove Save refuses rather than clobbering.
	lock := first.Path() + ".lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(lock) })
	_ = f.Close()

	second, err := Open(o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = second.Put(Entry{Name: "b", Key: "B", Value: secret.Secret("v")})
	if err := second.Save(); !errors.Is(err, ErrLocked) {
		t.Errorf("Save while locked = %v, want ErrLocked", err)
	}

	// The first writer's entry survived.
	reopened, _ := Open(o)
	if _, ok := reopened.Get("a"); !ok {
		t.Error("the held lock did not protect the existing entry")
	}
}

func TestAStaleLockIsBrokenRatherThanBlockingForever(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	lock := v.Path() + ".lock"
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	stale := time.Now().Add(-2 * lockStaleAfter)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}

	_ = v.Put(Entry{Name: "b", Key: "B", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Errorf("Save with a stale lock = %v, want it broken and the save to proceed", err)
	}
}

// A crash mid-write must leave the previous vault, never a truncated one.
func TestSaveLeavesNoTemporaryFileBehind(t *testing.T) {
	o, _ := opts(t)
	v, _ := Open(o)
	_ = v.Put(Entry{Name: "a", Key: "A", Value: secret.Secret("v")})
	if err := v.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(v.Path()))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "vault" {
			t.Errorf("stray file left in ~/.warden: %s", e.Name())
		}
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/vault/ -run 'TestOpen|TestSave|TestArgon|TestInit|TestPut|TestList|TestRemove|TestTwo|TestAn|TestThe|TestA' -v`
Expected: FAIL — `undefined: Open`, `undefined: Options`, `undefined: lockStaleAfter`, and so on.

- [ ] **Step 4: Write `internal/vault/vault.go`**

```go
package vault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/secret"
)

var (
	// ErrNoVault means there is no vault, or no such entry in it.
	ErrNoVault = errors.New("no such vault entry")
	// ErrExists means init was asked to create a vault that already exists.
	ErrExists = errors.New("a vault already exists")
	// ErrLocked means another warden process is writing.
	ErrLocked = errors.New("the vault is being written by another process")
	// ErrNoMasterKey means the file exists but its key does not. This is
	// unrecoverable, and warden must never respond by generating a new one.
	ErrNoMasterKey = errors.New("the vault's master key is missing")
)

// lockStaleAfter is how long a lockfile may exist before it is assumed to
// belong to a process that died.
const lockStaleAfter = 30 * time.Second

// argon2id parameters. Deliberately modest: this runs on every command in
// passphrase mode, and the passphrase path already carries a dialog.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// Options configures a vault. Keyring, Prompt and Now are injected so tests
// never touch a real keyring, a real dialog, or a real clock.
type Options struct {
	Home    string
	Keyring keyring.Keyring
	Prompt  prompt.Prompter
	Now     func() time.Time
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

func (o Options) kr() keyring.Keyring {
	if o.Keyring == nil {
		return keyring.Default()
	}
	return o.Keyring
}

// Path is the vault file for a home directory.
func Path(home string) string { return filepath.Join(home, ".warden", "vault") }

// V is an open vault.
type V struct {
	opts     Options
	path     string
	hdr      header
	key      []byte
	entries  []Entry
	exists   bool
	loosened bool
}

// Init creates an empty vault in the given mode, refusing to overwrite one.
//
// Bare `vault set` reaches Save without an Init, which creates a keyring-mode
// vault implicitly. Init exists for the other direction: choosing argon2id on a
// machine that does have a keyring.
func Init(o Options, mode Mode) error {
	path := Path(o.Home)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w at %s", ErrExists, path)
	}
	v := &V{opts: o, path: path, hdr: header{Mode: mode}}
	if err := v.establishKey(); err != nil {
		return err
	}
	return v.Save()
}

// Open reads and unseals the vault. A missing file is not an error: reads treat
// it as empty, and only Save creates one.
func Open(o Options) (*V, error) {
	path := Path(o.Home)
	v := &V{opts: o, path: path, hdr: header{Mode: ModeKeyring}}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	v.exists = true

	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		v.loosened = true
	}

	line, body, ok := strings.Cut(string(raw), "\n")
	if !ok {
		return nil, fmt.Errorf("%w: the file has no body", ErrBadFormat)
	}
	if v.hdr, err = parseHeader(line); err != nil {
		return nil, err
	}

	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if err != nil {
		return nil, fmt.Errorf("%w: the body is not valid base64", ErrBadFormat)
	}
	if err := v.resolveKey(); err != nil {
		return nil, err
	}
	if v.entries, err = openDoc(v.key, blob); err != nil {
		return nil, err
	}
	return v, nil
}

// Path is the backing file, safe to show a user.
func (v *V) Path() string { return v.path }

// Mode is how this vault's key is derived.
func (v *V) Mode() Mode { return v.hdr.Mode }

// Exists reports whether the file was there when this vault was opened.
func (v *V) Exists() bool { return v.exists }

// Loosened reports that the file was found more permissive than 0600. Save
// corrects it; the caller decides whether to mention it.
func (v *V) Loosened() bool { return v.loosened }

// List returns every unexpired entry, sorted by name.
func (v *V) List() []Entry {
	now := v.opts.now()
	out := make([]Entry, 0, len(v.entries))
	for _, e := range v.entries {
		if !e.ExpiredAt(now) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get resolves a name. An expired entry is reported as absent, which is what
// makes expiry indistinguishable from never having existed.
func (v *V) Get(name string) (Entry, bool) {
	now := v.opts.now()
	for _, e := range v.entries {
		if e.Name == name && !e.ExpiredAt(now) {
			return e, true
		}
	}
	return Entry{}, false
}

// Put adds or replaces an entry by name, stamping Created from the clock.
func (v *V) Put(e Entry) error {
	if err := ValidateName(e.Name); err != nil {
		return err
	}
	if err := ValidateKey(e.Key); err != nil {
		return err
	}
	now := v.opts.now()
	if !e.Permanent() {
		if err := ValidateTTL(e.Expires.Sub(now)); err != nil {
			return err
		}
	}
	if e.Created.IsZero() {
		e.Created = now
	}

	for i := range v.entries {
		if v.entries[i].Name == e.Name {
			v.entries[i] = e
			return nil
		}
	}
	v.entries = append(v.entries, e)
	return nil
}

// Remove drops an entry, reporting whether it was there.
func (v *V) Remove(name string) bool {
	for i := range v.entries {
		if v.entries[i].Name == name {
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			return true
		}
	}
	return false
}

// Rename moves an entry to a new name.
func (v *V) Rename(old, next string) error {
	if err := ValidateName(next); err != nil {
		return err
	}
	if _, ok := v.Get(old); !ok {
		return fmt.Errorf("%q: %w", old, ErrNoVault)
	}
	if _, taken := v.Get(next); taken && next != old {
		return fmt.Errorf("%q: %w", next, ErrExists)
	}
	for i := range v.entries {
		if v.entries[i].Name == old {
			v.entries[i].Name = next
			return nil
		}
	}
	return fmt.Errorf("%q: %w", old, ErrNoVault)
}

// Save purges expired entries, reseals the whole file, and lands it atomically.
//
// The whole document reseals on every write, so two processes writing at once
// would have the second silently drop the first's entry. The lockfile is what
// stops that.
func (v *V) Save() error {
	if err := v.establishKey(); err != nil {
		return err
	}
	return withLock(v.path, func() error {
		now := v.opts.now()
		kept := make([]Entry, 0, len(v.entries))
		for _, e := range v.entries {
			if !e.ExpiredAt(now) {
				kept = append(kept, e)
			}
		}
		v.entries = kept

		blob, err := sealDoc(v.key, v.entries)
		if err != nil {
			return err
		}
		body := renderHeader(v.hdr) + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n"

		if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", filepath.Dir(v.path), err)
		}
		tmp := v.path + ".tmp"
		if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
			return fmt.Errorf("writing the vault: %w", err)
		}
		if err := os.Rename(tmp, v.path); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("replacing the vault: %w", err)
		}
		// A pre-existing file keeps its own mode through a rename on some
		// systems, so assert it rather than trusting WriteFile's.
		if err := os.Chmod(v.path, 0o600); err != nil {
			return fmt.Errorf("setting permissions: %w", err)
		}
		v.exists, v.loosened = true, false
		return nil
	})
}

// establishKey obtains the key for a write, creating one on first use.
func (v *V) establishKey() error {
	if len(v.key) == keyLen {
		return nil
	}
	if v.hdr.Mode == ModeArgon2id {
		return v.deriveFromPassphrase()
	}

	kr := v.opts.kr()
	mk, err := kr.Get()
	switch {
	case err == nil:
		return v.decodeMasterKey(mk)
	case errors.Is(err, keyring.ErrNotFound) && !v.exists:
		// First use: mint a key and store it.
		key := make([]byte, keyLen)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("generating a master key: %w", err)
		}
		encoded := base64.StdEncoding.EncodeToString(key)
		if err := kr.Set(secret.Secret(encoded)); err != nil {
			return err
		}
		v.key = key
		return nil
	case errors.Is(err, keyring.ErrNotFound):
		return v.noMasterKey()
	case errors.Is(err, keyring.ErrUnavailable):
		return fmt.Errorf(
			"%w: this machine offers no keyring — create a passphrase vault instead with "+
				"`warden vault init --passphrase`", err)
	default:
		return err
	}
}

// resolveKey obtains the key for a read of an existing file.
func (v *V) resolveKey() error {
	if v.hdr.Mode == ModeArgon2id {
		return v.deriveFromPassphrase()
	}
	mk, err := v.opts.kr().Get()
	switch {
	case err == nil:
		return v.decodeMasterKey(mk)
	case errors.Is(err, keyring.ErrNotFound):
		return v.noMasterKey()
	case errors.Is(err, keyring.ErrUnavailable):
		return fmt.Errorf(
			"%w: this vault was sealed with a keyring key and this machine has no keyring", ErrNoMasterKey)
	default:
		return err
	}
}

// noMasterKey is the unrecoverable case: the file is here and its key is not.
//
// Generating a fresh key and resealing would present total data loss as
// success, so warden refuses and names both real options instead.
func (v *V) noMasterKey() error {
	return fmt.Errorf(
		"%w — %s was sealed with a key that is no longer in this machine's keychain. "+
			"Warden will not create a new one, because that would silently discard every entry. "+
			"Either restore the keychain item (service %q, account %q), or delete %s and start over",
		ErrNoMasterKey, v.path, "warden", "vault-master", v.path)
}

func (v *V) decodeMasterKey(mk secret.Secret) error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(mk.Expose()))
	if err != nil {
		return fmt.Errorf("%w: the stored master key is not valid base64", ErrNoMasterKey)
	}
	if len(key) != keyLen {
		return fmt.Errorf("%w: the stored master key is %d bytes, want %d", ErrNoMasterKey, len(key), keyLen)
	}
	v.key = key
	return nil
}

// deriveFromPassphrase collects the passphrase through the prompt — the same
// channel set --secret uses, so it never passes through a calling agent.
func (v *V) deriveFromPassphrase() error {
	if len(v.hdr.Salt) == 0 {
		salt := make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return fmt.Errorf("generating a salt: %w", err)
		}
		v.hdr.Salt = salt
	}
	p := v.opts.Prompt
	if p == nil {
		p = prompt.Default()
	}
	pass, err := p.AskSecret("vault passphrase", v.path)
	if err != nil {
		return err
	}
	v.key = argon2.IDKey([]byte(pass.Expose()), v.hdr.Salt, argonTime, argonMemory, argonThreads, keyLen)
	return nil
}

// withLock serialises writers through an O_EXCL lockfile, breaking one left
// behind by a process that died.
func withLock(path string, fn func() error) error {
	lock := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(lock), err)
	}

	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		fi, statErr := os.Stat(lock)
		if statErr != nil || time.Since(fi.ModTime()) < lockStaleAfter {
			return fmt.Errorf("%w (lock: %s)", ErrLocked, lock)
		}
		// Stale: the holder is gone. Break it and take it once.
		_ = os.Remove(lock)
		if f, err = os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
			return fmt.Errorf("%w (lock: %s)", ErrLocked, lock)
		}
	} else if err != nil {
		return fmt.Errorf("taking the vault lock: %w", err)
	}
	_ = f.Close()
	defer func() { _ = os.Remove(lock) }()

	return fn()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/vault/ -v`
Expected: PASS, every test in both files.

- [ ] **Step 6: Raise the `Expose()` budget — the suite fails until you do**

`internal/cli/arch_test.go` caps how many production `Expose()` call sites may
exist, and this task added three: sealing entry values, deriving the passphrase
key, and decoding the master key. Task 1 added two more (each backend's `Set`).
The count is now 9 against a budget of 6, so `go test ./...` fails on
`TestExposeCallSitesStayFew` until the budget moves.

Set it to 10 now — Task 4 adds the tenth, `write.setFromVault` — and name every
site, because the comment is what makes the number reviewable.

In `internal/cli/arch_test.go`, replace:

```go
	// classify (shape check), query.Get, write.SetPublic, write.SetSecret.
	const budget = 6
```

with:

```go
	// classify (shape check), query.Get, write.SetPublic, write.SetSecret,
	// vault sealDoc (the wire type that defeats Secret redaction),
	// vault deriveFromPassphrase, vault decodeMasterKey,
	// keyring Security.Set and SecretTool.Set (stdin, never argv),
	// write.setFromVault (the value crossing on vault push).
	const budget = 10
```

Verify the count matches what you expect:

```bash
grep -rn --include='*.go' '.Expose()' . | grep -v _test.go | wc -l
```
Expected: `9` at this point in the plan. If it is higher, a call site was added
that this plan did not account for — find it before raising the number.

- [ ] **Step 7: Verify the build stays cgo-free and the suite is green**

Run: `CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...`
Expected: all PASS. `golang.org/x/crypto` is pure Go, so a cgo failure here means something else was pulled in.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/vault internal/cli/arch_test.go
git commit -m "feat(vault): open, save and resolve the master key

Open on a missing file yields an empty vault, so reads treat 'no vault' as
'no entries' and only Save creates one. Get refuses an expired entry, which
is what makes expiry indistinguishable from never having existed; Save
purges what has lapsed.

The refusal that matters most: a file whose keyring key is gone is
unrecoverable, and warden will not mint a new one. Doing so would reseal an
empty document over the user's entries and report success. It names both
real options instead — restore the keychain item, or delete the file.

Writes take an O_EXCL lockfile because the whole document reseals each time,
so an unguarded second writer would drop the first writer's entry."
```

---

## Task 4: `internal/query` and `internal/write` — the only doors in

**Files:**
- Create: `internal/query/vault.go`
- Create: `internal/write/vault.go`
- Modify: `internal/write/write.go` (add unexported `has` and `setFromVault`)
- Test: `internal/write/vault_test.go`
- Test: `internal/query/vault_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–3; `query.Scope`, `write.Open`, `prompt.Prompter`.
- Produces:
  - `query.VaultKeyring keyring.Keyring` and `query.VaultNow func() time.Time` — test seams, nil means production defaults.
  - `query.VaultRow{Name, Key string, Created, Expires time.Time, Permanent bool}`.
  - `query.OpenVault(home string, p prompt.Prompter) (*query.VQ, error)`; on `*VQ`: `Path() string`, `Exists() bool`, `Loosened() bool`, `Mode() string`, `List() []VaultRow`, `Has(name string) bool`.
  - `write.InitVault(home string, p prompt.Prompter, passphrase bool) error`.
  - `write.OpenVault(home string, p prompt.Prompter) (*write.VW, error)`; on `*VW`: `Path() string`, `Set(name, key string, ttl time.Duration) error`, `Edit(name string, o write.EditOpts) error`, `Remove(name string) error`, `Push(name string, dest query.Scope, as string, force, yes bool) (write.PushResult, error)`.
  - `write.EditOpts{NewName, NewKey string, TTL *time.Duration}` — `TTL` nil leaves the deadline alone, a pointer to `0` clears it.
  - `write.PushResult{Key, Path string}`; `write.ErrDestinationSet`.

**Why the prompter is a parameter but the keyring is a package var:** the prompter is already threaded through both surfaces (`cli.SetPrompter`, `mcpserver.New(p)`), so `OpenVault` takes it like every other write path. The keyring and clock have no such thread and only tests need to replace them, so they follow the `cli.SetPrompter` precedent as assignable package vars. Both are needed because `internal/cli` may not import `internal/keyring` — the architecture test forbids it — while `internal/cli`'s *test* files may, since the test inspects `.Imports` rather than `.TestImports`.

- [ ] **Step 1: Write the failing tests for the read side**

Create `internal/query/vault_test.go`:

```go
package query

import (
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/secret"
	"github.com/hadefication/warden/internal/vault"
)

var vaultNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

// seedVault writes a vault into a temp home through internal/vault directly,
// which is what the query package is a read-only view over.
func seedVault(t *testing.T, entries ...vault.Entry) (home string, kr *keyring.Fake) {
	t.Helper()
	home = t.TempDir()
	kr = &keyring.Fake{}

	v, err := vault.Open(vault.Options{
		Home: home, Keyring: kr, Prompt: prompt.Fake{}, Now: func() time.Time { return vaultNow },
	})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for _, e := range entries {
		if err := v.Put(e); err != nil {
			t.Fatalf("seed put %q: %v", e.Name, err)
		}
	}
	if err := v.Save(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	VaultKeyring = kr
	VaultNow = func() time.Time { return vaultNow }
	t.Cleanup(func() { VaultKeyring, VaultNow = nil, nil })
	return home, kr
}

func TestVaultListReturnsMetadataAndNoValues(t *testing.T) {
	home, _ := seedVault(t,
		vault.Entry{Name: "stripe/live", Key: "STRIPE_SECRET", Value: secret.Secret("marker-a")},
		vault.Entry{Name: "tmp/token", Key: "TMP_TOKEN", Value: secret.Secret("marker-b"),
			Expires: vaultNow.Add(3 * time.Hour)},
	)

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	rows := q.List()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Name != "stripe/live" || rows[0].Key != "STRIPE_SECRET" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if !rows[0].Permanent {
		t.Error("stripe/live has no deadline and should be permanent")
	}
	if rows[1].Permanent || !rows[1].Expires.Equal(vaultNow.Add(3*time.Hour)) {
		t.Errorf("row 1 = %+v, want a deadline three hours out", rows[1])
	}
	// VaultRow deliberately has no value field. This is the compile-time half of
	// the guarantee; the canary suite is the runtime half.
}

func TestVaultHasIgnoresExpiredEntries(t *testing.T) {
	home, _ := seedVault(t,
		vault.Entry{Name: "live", Key: "A", Value: secret.Secret("v"), Expires: vaultNow.Add(time.Hour)},
		vault.Entry{Name: "dead", Key: "B", Value: secret.Secret("v"), Expires: vaultNow.Add(time.Minute)},
	)

	later := vaultNow.Add(30 * time.Minute)
	VaultNow = func() time.Time { return later }

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if !q.Has("live") {
		t.Error("Has(live) = false, want true")
	}
	if q.Has("dead") {
		t.Error("Has(dead) = true — an expired entry must read as absent")
	}
	if q.Has("never-existed") {
		t.Error("Has of an unknown name should be false")
	}
}

func TestOpenVaultOnAMissingVaultIsEmptyRatherThanAnError(t *testing.T) {
	home := t.TempDir()
	VaultKeyring = &keyring.Fake{}
	t.Cleanup(func() { VaultKeyring = nil })

	q, err := OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault on a missing vault = %v, want nil", err)
	}
	if q.Exists() {
		t.Error("Exists should be false")
	}
	if len(q.List()) != 0 {
		t.Error("List should be empty")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/query/ -run TestVault -v`
Expected: FAIL — `undefined: OpenVault`, `undefined: VaultKeyring`.

- [ ] **Step 3: Write `internal/query/vault.go`**

```go
package query

import (
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/vault"
)

// VaultKeyring and VaultNow are test seams, following the cli.SetPrompter
// precedent. Nil means the production default. Nothing but a test should assign
// them: internal/cli may not import internal/keyring at all, so this is how a
// test drives the vault surface without a real keychain.
var (
	VaultKeyring keyring.Keyring
	VaultNow     func() time.Time
)

// VaultRow is one entry's public-facing summary. It deliberately has no value
// field — the same rule Row follows for .env.
type VaultRow struct {
	Name      string
	Key       string
	Created   time.Time
	Expires   time.Time
	Permanent bool
}

// VQ is an open, read-only view of the vault.
type VQ struct{ v *vault.V }

// OpenVault reads the vault under home. A missing vault is not an error: it
// reads as empty, exactly as a missing entry does.
//
// p collects the passphrase for a vault in argon2id mode. A keyring-mode vault
// never reaches it.
func OpenVault(home string, p prompt.Prompter) (*VQ, error) {
	v, err := vault.Open(vaultOptions(home, p))
	if err != nil {
		return nil, err
	}
	return &VQ{v: v}, nil
}

func vaultOptions(home string, p prompt.Prompter) vault.Options {
	return vault.Options{
		Home:    home,
		Keyring: VaultKeyring,
		Prompt:  p,
		Now:     VaultNow,
	}
}

// Path is the backing file, safe to show a user.
func (q *VQ) Path() string { return q.v.Path() }

// Exists reports whether a vault file is there at all.
func (q *VQ) Exists() bool { return q.v.Exists() }

// Loosened reports that the vault was found more permissive than 0600.
func (q *VQ) Loosened() bool { return q.v.Loosened() }

// Mode names how the vault's key is derived: "keyring" or "argon2id".
func (q *VQ) Mode() string { return string(q.v.Mode()) }

// List summarises every unexpired entry, in name order.
func (q *VQ) List() []VaultRow {
	entries := q.v.List()
	rows := make([]VaultRow, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, VaultRow{
			Name:      e.Name,
			Key:       e.Key,
			Created:   e.Created,
			Expires:   e.Expires,
			Permanent: e.Permanent(),
		})
	}
	return rows
}

// Has reports whether a live entry exists under name. An expired entry is
// absent, which is what makes expiry indistinguishable from never having been.
func (q *VQ) Has(name string) bool {
	_, ok := q.v.Get(name)
	return ok
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/query/ -v`
Expected: PASS, including the pre-existing query tests.

- [ ] **Step 5: Write the failing tests for the write side**

Create `internal/write/vault_test.go`:

```go
package write

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
)

const vaultMarker = "vault-marker-8be40c17"

var wNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

func vaultHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	query.VaultKeyring = &keyring.Fake{}
	query.VaultNow = func() time.Time { return wNow }
	t.Cleanup(func() { query.VaultKeyring, query.VaultNow = nil, nil })
	return home
}

// project makes a .env to push into.
func project(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVaultSetStoresWhatTheUserTyped(t *testing.T) {
	home := vaultHome(t)
	w, err := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if err := w.Set("stripe/live", "STRIPE_SECRET", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	q, err := query.OpenVault(home, prompt.Fake{})
	if err != nil {
		t.Fatalf("OpenVault (read): %v", err)
	}
	if !q.Has("stripe/live") {
		t.Fatal("the entry was not persisted")
	}
	if rows := q.List(); rows[0].Key != "STRIPE_SECRET" || !rows[0].Permanent {
		t.Errorf("row = %+v, want STRIPE_SECRET and permanent", rows[0])
	}
}

func TestVaultSetWithATTLStampsADeadline(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("tmp", "TMP_TOKEN", 8*time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	row := q.List()[0]
	if row.Permanent {
		t.Fatal("an entry given a ttl is not permanent")
	}
	if !row.Expires.Equal(wNow.Add(8 * time.Hour)) {
		t.Errorf("expires = %v, want %v", row.Expires, wNow.Add(8*time.Hour))
	}
}

// Nothing may be written when the prompt is declined.
func TestVaultSetWritesNothingWhenTheUserCancels(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Err: prompt.ErrCancelled})
	if err := w.Set("a", "A", 0); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("Set = %v, want ErrCancelled", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".warden", "vault")); !os.IsNotExist(err) {
		t.Error("a cancelled Set created a vault file")
	}
}

// Replacing a live value destroys something that may not be recoverable, so it
// takes the plain ceremony — never the retype, which means disclosure.
func TestVaultSetOverAnExistingEntryAsksForConfirmation(t *testing.T) {
	home := vaultHome(t)
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action+":"+key) },
	}

	w, _ := OpenVault(home, p)
	if err := w.Set("a", "A", 0); err != nil {
		t.Fatalf("first Set: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("a new entry should not need confirming, got %v", actions)
	}

	w2, _ := OpenVault(home, p)
	if err := w2.Set("a", "A", 0); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if len(actions) != 1 || !strings.HasPrefix(actions[0], "replace:") {
		t.Errorf("actions = %v, want one replace confirmation", actions)
	}
}

func TestVaultRemoveConfirmsAndDeletes(t *testing.T) {
	home := vaultHome(t)
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action) },
	}
	w, _ := OpenVault(home, p)
	if err := w.Set("a", "A", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := w.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(actions) != 1 || actions[0] != "remove" {
		t.Errorf("actions = %v, want one remove confirmation", actions)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if q.Has("a") {
		t.Error("the entry survived Remove")
	}
}

func TestVaultRemoveOfAnAbsentEntryIsRefusedWithoutAsking(t *testing.T) {
	home := vaultHome(t)
	asked := false
	p := prompt.Fake{OnAction: func(string, string, string) { asked = true }}
	w, _ := OpenVault(home, p)

	if err := w.Remove("nope"); err == nil {
		t.Fatal("want an error")
	}
	if asked {
		t.Error("the user was asked to authorise removing something that is not there")
	}
}

func TestVaultEditChangesNameKeyAndTTL(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("old", "OLD_KEY", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	ttl := 2 * time.Hour
	if err := w.Edit("old", EditOpts{NewName: "new/name", NewKey: "NEW_KEY", TTL: &ttl}); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if q.Has("old") {
		t.Error("the old name still resolves")
	}
	row := q.List()[0]
	if row.Name != "new/name" || row.Key != "NEW_KEY" {
		t.Errorf("row = %+v", row)
	}
	if !row.Expires.Equal(wNow.Add(2 * time.Hour)) {
		t.Errorf("expires = %v, want a two-hour window", row.Expires)
	}
}

func TestVaultEditCanClearATTL(t *testing.T) {
	home := vaultHome(t)
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("a", "A", time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}
	var none time.Duration
	if err := w.Edit("a", EditOpts{TTL: &none}); err != nil {
		t.Fatalf("Edit: %v", err)
	}

	q, _ := query.OpenVault(home, prompt.Fake{})
	if !q.List()[0].Permanent {
		t.Error("clearing the ttl should make the entry permanent")
	}
}

// The value must cross into the .env intact. This is the end-to-end half of the
// redaction trap: if a Secret were marshalled anywhere on this path, the project
// would receive the literal string "<redacted>".
func TestVaultPushWritesTheRealValueIntoTheDestination(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "APP_NAME=demo\n")

	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("stripe/live", "STRIPE_SECRET", 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	res, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", false, true)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if res.Key != "STRIPE_SECRET" {
		t.Errorf("res.Key = %q", res.Key)
	}

	body, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "STRIPE_SECRET="+vaultMarker) {
		t.Fatalf("the destination did not receive the value:\n%s", body)
	}
	if strings.Contains(string(body), "<redacted>") {
		t.Fatal("the destination received the redaction marker instead of the value")
	}
}

func TestVaultPushRenamesInFlightWithAs(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("stripe/live", "STRIPE_SECRET", 0)

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "STRIPE_KEY", false, true); err != nil {
		t.Fatalf("Push: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "STRIPE_KEY="+vaultMarker) {
		t.Errorf("--as did not rename the key:\n%s", body)
	}
}

func TestVaultPushRefusesAnAlreadySetDestinationKeyUnlessForced(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "STRIPE_SECRET=already-here\n")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("stripe/live", "STRIPE_SECRET", 0)

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", false, true); !errors.Is(err, ErrDestinationSet) {
		t.Fatalf("Push = %v, want ErrDestinationSet", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "already-here") {
		t.Fatal("the refused push overwrote the destination anyway")
	}

	if _, err := w.Push("stripe/live", query.Scope{Dir: dir}, "", true, true); err != nil {
		t.Fatalf("forced Push: %v", err)
	}
	body, _ = os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "STRIPE_SECRET="+vaultMarker) {
		t.Errorf("--force did not overwrite:\n%s", body)
	}
}

// Push moves a credential into a file that may well be committed, so it asks.
func TestVaultPushConfirmsUnlessYes(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	var actions []string
	p := prompt.Fake{
		Value:    vaultMarker,
		OnAction: func(action, key, path string) { actions = append(actions, action+":"+key) },
	}
	w, _ := OpenVault(home, p)
	_ = w.Set("a", "A_TOKEN", 0)

	if _, err := w.Push("a", query.Scope{Dir: dir}, "", false, false); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if len(actions) != 1 || actions[0] != "push:A_TOKEN" {
		t.Errorf("actions = %v, want one push confirmation naming the key", actions)
	}
}

func TestVaultPushWritesNothingWhenTheConfirmationIsDeclined(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	_ = w.Set("a", "A_TOKEN", 0)

	declining, _ := OpenVault(home, prompt.Fake{
		Value:      vaultMarker,
		ConfirmErr: prompt.ErrCancelled,
	})
	// ConfirmAction on prompt.Fake returns ConfirmErr, so this push is declined.
	if _, err := declining.Push("a", query.Scope{Dir: dir}, "", false, false); !errors.Is(err, prompt.ErrCancelled) {
		t.Fatalf("Push = %v, want ErrCancelled", err)
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if strings.Contains(string(body), vaultMarker) {
		t.Fatal("a declined push wrote the value anyway")
	}
}

func TestVaultPushOfAnAbsentOrExpiredEntryFails(t *testing.T) {
	home := vaultHome(t)
	dir := project(t, "")
	w, _ := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err := w.Set("gone", "GONE", time.Hour); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Roll the clock past the deadline and reopen.
	query.VaultNow = func() time.Time { return wNow.Add(2 * time.Hour) }
	later, err := OpenVault(home, prompt.Fake{Value: vaultMarker})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if _, err := later.Push("gone", query.Scope{Dir: dir}, "", false, true); err == nil {
		t.Error("pushing an expired entry should fail as absent")
	}
	if _, err := later.Push("never", query.Scope{Dir: dir}, "", false, true); err == nil {
		t.Error("pushing an unknown entry should fail")
	}
}

func TestInitVaultPassphraseModeIsRecorded(t *testing.T) {
	home := vaultHome(t)
	if err := InitVault(home, prompt.Fake{Value: "a-passphrase"}, true); err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	q, err := query.OpenVault(home, prompt.Fake{Value: "a-passphrase"})
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if q.Mode() != "argon2id" {
		t.Errorf("mode = %q, want argon2id", q.Mode())
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./internal/write/ -run TestVault -v`
Expected: FAIL — `undefined: OpenVault`, `undefined: EditOpts`, `undefined: ErrDestinationSet`.

- [ ] **Step 7: Teach `internal/prompt` the vault's actions**

`ConfirmAction` renders its dialog from `actionSentence`, whose `default` branch
reads *"Remove %s. Its value will be gone from this file."* The vault introduces
`replace`, `edit` and `push`, so as it stands a push would show the user a dialog
saying they are **removing** a key — they would be authorising the wrong thing.
`actionCommand`, which names the command to run when there is no dialog, has the
same problem: it would print `warden unset <KEY>` for a push.

Add the test to `internal/prompt/action_test.go`:

```go
// A dialog that misnames the action is worse than no dialog: the user authorises
// something other than what happens. The vault added three actions, and the
// default branch called every one of them a removal.
func TestEveryActionHasItsOwnSentenceAndCommand(t *testing.T) {
	for _, tc := range []struct {
		action   string
		wantWord string
		wantCmd  string
	}{
		{"remove", "Remove", "warden unset GH_TOKEN"},
		{"clear", "Clear", "warden clear GH_TOKEN"},
		{"replace", "Replace", "warden vault set GH_TOKEN"},
		{"edit", "Change", "warden vault edit GH_TOKEN"},
		{"push", "Write", "warden vault push GH_TOKEN"},
	} {
		t.Run(tc.action, func(t *testing.T) {
			got := actionSentence(tc.action, "GH_TOKEN")
			if !strings.HasPrefix(got, tc.wantWord) {
				t.Errorf("actionSentence(%q) = %q, want it to start with %q",
					tc.action, got, tc.wantWord)
			}
			if !strings.Contains(got, "GH_TOKEN") {
				t.Errorf("actionSentence(%q) = %q, should name the key", tc.action, got)
			}
			if cmd := actionCommand(tc.action, "GH_TOKEN"); cmd != tc.wantCmd {
				t.Errorf("actionCommand(%q) = %q, want %q", tc.action, cmd, tc.wantCmd)
			}
		})
	}
}

// A push is the one action whose dialog must say where the value is going, since
// that is the whole risk being authorised.
func TestThePushSentenceDoesNotClaimToRemoveAnything(t *testing.T) {
	got := actionSentence("push", "STRIPE_SECRET")
	for _, wrong := range []string{"Remove", "gone"} {
		if strings.Contains(got, wrong) {
			t.Errorf("the push sentence contains %q: %q", wrong, got)
		}
	}
}
```

Add `"strings"` to that file's imports if it is not already there, then replace
both functions in `internal/prompt/confirm.go`:

```go
func actionSentence(action, key string) string {
	switch action {
	case "clear":
		return fmt.Sprintf("Clear the value of %s, leaving the key declared and empty.", key)
	case "replace":
		return fmt.Sprintf(
			"Replace the value stored for %s. The value it holds now cannot be recovered.", key)
	case "edit":
		return fmt.Sprintf(
			"Change %s. Its value is untouched, but anything pushing it by its old name or key "+
				"will stop finding it.", key)
	case "push":
		return fmt.Sprintf(
			"Write the vault's value for %s into this file. Check the path below: a credential "+
				"that exists nowhere else is about to live somewhere that may be committed.", key)
	default:
		return fmt.Sprintf("Remove %s. Its value will be gone from this file.", key)
	}
}

// actionCommand names the command the user can run themselves when there is no
// channel to ask them through. Every action needs its own: telling someone to
// run `warden unset` when they asked to push is worse than telling them nothing.
func actionCommand(action, key string) string {
	switch action {
	case "clear":
		return "warden clear " + key
	case "replace":
		return "warden vault set " + key
	case "edit":
		return "warden vault edit " + key
	case "push":
		return "warden vault push " + key
	default:
		return "warden unset " + key
	}
}
```

Run: `go test ./internal/prompt/ -v`
Expected: PASS. The new cases fail before the switch statements are replaced,
which is the point — the default branch silently mislabelled all three.

- [ ] **Step 8: Add the two unexported helpers to `internal/write/write.go`**

Append to `internal/write/write.go`:

```go
// has reports whether the destination store already holds a usable value for
// key. Push consults it so a push cannot silently overwrite a value the project
// is currently running on.
func (w *W) has(key string) bool {
	v, ok := w.st.Get(key)
	return ok && v.IsSet()
}

// setFromVault writes a value that came from the vault rather than from a
// prompt.
//
// It exists because Push must not go through SetSecret, which would ask the user
// to type a value warden is already holding, and must not go through SetPublic,
// which refuses credential-shaped values — refusing them is right for a caller
// handing warden a value, and wrong for warden moving its own. The value crosses
// as a secret.Secret and is exposed here, at one reviewed call site.
func (w *W) setFromVault(key string, v secret.Secret) error {
	return w.st.Set(key, v.Expose())
}
```

- [ ] **Step 9: Write `internal/write/vault.go`**

```go
package write

import (
	"errors"
	"fmt"
	"time"

	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
	"github.com/hadefication/warden/internal/vault"
)

// ErrDestinationSet means the destination already holds a value for the key, and
// the push was not forced.
var ErrDestinationSet = errors.New("the destination key is already set")

// EditOpts are the metadata changes Edit applies. A zero field leaves that
// property alone; TTL is a pointer so that clearing a deadline (a pointer to 0)
// is distinguishable from not touching it (nil).
type EditOpts struct {
	NewName string
	NewKey  string
	TTL     *time.Duration
}

// VW is an open, writable view of the vault.
type VW struct {
	v    *vault.V
	p    prompt.Prompter
	home string
}

// InitVault creates an empty vault, choosing how its key is derived.
//
// Bare `vault set` creates a keyring vault implicitly, so this exists for the
// other direction: opting into a passphrase on a machine that has a keyring.
func InitVault(home string, p prompt.Prompter, passphrase bool) error {
	mode := vault.ModeKeyring
	if passphrase {
		mode = vault.ModeArgon2id
	}
	return vault.Init(vaultOptions(home, p), mode)
}

// OpenVault opens the vault under home for writing.
func OpenVault(home string, p prompt.Prompter) (*VW, error) {
	v, err := vault.Open(vaultOptions(home, p))
	if err != nil {
		return nil, err
	}
	return &VW{v: v, p: p, home: home}, nil
}

// vaultOptions mirrors query's, so both surfaces honour the same test seams.
func vaultOptions(home string, p prompt.Prompter) vault.Options {
	return vault.Options{
		Home:    home,
		Keyring: query.VaultKeyring,
		Prompt:  p,
		Now:     query.VaultNow,
	}
}

// Path is the vault file.
func (w *VW) Path() string { return w.v.Path() }

// Set stores a value typed at the prompt under name, targeting key.
//
// Replacing a live entry asks first: what is at stake is a value the user may
// not be able to recover, which is destruction rather than disclosure, so it
// takes the plain ceremony and never the retype.
func (w *VW) Set(name, key string, ttl time.Duration) error {
	if err := vault.ValidateName(name); err != nil {
		return err
	}
	if err := vault.ValidateKey(key); err != nil {
		return err
	}
	if err := vault.ValidateTTL(ttl); err != nil {
		return err
	}

	if _, exists := w.v.Get(name); exists {
		if err := w.p.ConfirmAction("replace", name, w.v.Path()); err != nil {
			return err
		}
	}

	value, err := w.p.AskSecret(name, w.v.Path())
	if err != nil {
		return err
	}

	e := vault.Entry{Name: name, Key: key, Value: value}
	if ttl > 0 {
		e.Expires = w.now().Add(ttl)
	}
	if err := w.v.Put(e); err != nil {
		return err
	}
	return w.v.Save()
}

// Edit changes an entry's metadata. It never touches the value, so there is
// nothing to disclose — but renaming and retargeting can strand a project, and
// shortening a window can strand a session, so it confirms.
func (w *VW) Edit(name string, o EditOpts) error {
	e, ok := w.v.Get(name)
	if !ok {
		return fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}
	if o.NewKey != "" {
		if err := vault.ValidateKey(o.NewKey); err != nil {
			return err
		}
	}
	if o.NewName != "" {
		if err := vault.ValidateName(o.NewName); err != nil {
			return err
		}
	}
	if o.TTL != nil {
		if err := vault.ValidateTTL(*o.TTL); err != nil {
			return err
		}
	}
	if err := w.p.ConfirmAction("edit", name, w.v.Path()); err != nil {
		return err
	}

	if o.NewKey != "" {
		e.Key = o.NewKey
	}
	if o.TTL != nil {
		if *o.TTL == 0 {
			e.Expires = time.Time{}
		} else {
			e.Expires = w.now().Add(*o.TTL)
		}
	}
	// Put replaces by name, so a rename is a remove plus a put under the new one.
	if o.NewName != "" && o.NewName != name {
		w.v.Remove(name)
		e.Name = o.NewName
	}
	if err := w.v.Put(e); err != nil {
		return err
	}
	return w.v.Save()
}

// Remove deletes an entry once the user authorises it. An absent entry is
// refused without asking: there is nothing to lose, and asking anyway would
// train the answer.
func (w *VW) Remove(name string) error {
	if _, ok := w.v.Get(name); !ok {
		return fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}
	if err := w.p.ConfirmAction("remove", name, w.v.Path()); err != nil {
		return err
	}
	w.v.Remove(name)
	return w.v.Save()
}

// PushResult reports where a value landed, with no value and no length.
type PushResult struct {
	Key  string
	Path string
}

// Push copies an entry's value into a destination store.
//
// This is the operation that moves a credential from a file that exists nowhere
// else into one that may well be committed, so it confirms by default. yes
// skips that and is reachable only from the CLI — the MCP surface never sets it.
//
// The value crosses inside a secret.Secret and is exposed once, in
// setFromVault. It is never formatted, never logged, and never in argv.
func (w *VW) Push(name string, dest query.Scope, as string, force, yes bool) (PushResult, error) {
	e, ok := w.v.Get(name)
	if !ok {
		return PushResult{}, fmt.Errorf("%q: %w", name, vault.ErrNoVault)
	}

	key := e.Key
	if as != "" {
		if err := vault.ValidateKey(as); err != nil {
			return PushResult{}, err
		}
		key = as
	}

	dw, err := Open(dest, w.p)
	if err != nil {
		return PushResult{}, err
	}
	if dw.has(key) && !force {
		return PushResult{}, fmt.Errorf(
			"%s in %s: %w — pass --force to overwrite it", key, dw.Path(), ErrDestinationSet)
	}
	if !yes {
		if err := w.p.ConfirmAction("push", key, dw.Path()); err != nil {
			return PushResult{}, err
		}
	}
	if err := dw.setFromVault(key, e.Value); err != nil {
		return PushResult{}, err
	}
	return PushResult{Key: key, Path: dw.Path()}, nil
}

func (w *VW) now() time.Time {
	if query.VaultNow != nil {
		return query.VaultNow()
	}
	return time.Now()
}
```

- [ ] **Step 10: Run the write tests to verify they pass**

Run: `go test ./internal/write/ -v`
Expected: PASS, including the pre-existing write tests.

- [ ] **Step 11: Confirm the Expose budget landed exactly where the plan said**

Run:
```bash
grep -rn --include='*.go' '.Expose()' . | grep -v _test.go | wc -l
```
Expected: `10`, matching the budget set in Task 3. A different number means a call site was added or removed that this plan did not account for — reconcile before continuing.

- [ ] **Step 12: Full suite**

Run: `CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 13: Commit**

```bash
git add internal/query/vault.go internal/query/vault_test.go internal/write/vault.go internal/write/vault_test.go internal/write/write.go internal/prompt/confirm.go internal/prompt/action_test.go
git commit -m "feat(vault): reach the vault through query and write only

The surfaces get a read view with no value field and a write view whose only
outbound path is Push. Push goes through neither SetSecret, which would ask
the user to type a value warden already holds, nor SetPublic, which refuses
credential-shaped values — right for a caller handing warden a value, wrong
for warden moving its own.

Push refuses an already-set destination key unless forced, and confirms by
default, because it moves a credential into a file that may well be
committed. --yes is a parameter rather than a default so the MCP surface can
decline to offer it.

VaultKeyring and VaultNow are test seams following the cli.SetPrompter
precedent: internal/cli may not import internal/keyring, and this is how its
tests drive the vault without a real keychain.

prompt's actionSentence defaulted to "Remove %s" for any action it did not
recognise, so a push dialog would have told the user they were removing a key
while warden wrote a credential into a file. Every action now has its own
sentence and its own run-it-yourself command."
```

---

## Task 5: the `vault` command family

**Files:**
- Create: `internal/cli/vault.go`
- Test: `internal/cli/vault_test.go`
- Modify: `internal/cli/cli.go` (one line: register the family)
- Modify: `internal/cli/arch_test.go` (forbid `internal/vault` and `internal/keyring`)
- Modify: `internal/cli/canary_test.go` (walk subcommands; add vault rows)
- Modify: `internal/cli/parity_test.go` (walk subcommands; add vault rows)

**Interfaces:**
- Consumes: `query.OpenVault`, `query.VaultRow`, `write.OpenVault`, `write.InitVault`, `write.EditOpts`, `write.PushResult`, `write.ErrDestinationSet`, `vault.ErrNoVault`/`ErrBadName`/`ErrBadKey`/`ErrTTLTooLong`/`ErrNoMasterKey`/`ErrLocked`, `cli.SetPrompter`, `cli.ExitError`.
- Produces: `addVaultCommands(root *cobra.Command, out io.Writer)`. The duration parser is **not** defined here: it lives as `vault.ParseTTL` and is reached via `query.ParseTTL`, because Task 6's MCP tools need the same parser and two copies would drift.

**Rules this task enforces:**
- `--global` is refused on every subcommand, with a message saying the vault is user-global already.
- `has` exits 1 for absent-or-expired and prints nothing, matching `warden has`.
- Everything else that fails exits 3. Exit code 2 is unreachable here.
- `--yes` exists only on `push`.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/vault_test.go`:

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hadefication/warden/internal/keyring"
	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
)

const cliVaultMarker = "cli-vault-marker-52ad"

// vaultEnv redirects $HOME and installs the fakes. No test may reach the real
// keychain or the real home directory.
func vaultEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	query.VaultKeyring = &keyring.Fake{}
	query.VaultNow = func() time.Time { return time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC) }
	prev := SetPrompter
	SetPrompter = prompt.Fake{Value: cliVaultMarker}
	t.Cleanup(func() {
		query.VaultKeyring, query.VaultNow = nil, nil
		SetPrompter = prev
	})
	return home
}

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errw bytes.Buffer
	err := Run(args, &out, &errw)
	return out.String(), errw.String(), ExitCode(err)
}

func TestVaultSetThenListShowsMetadataAndNoValue(t *testing.T) {
	vaultEnv(t)

	if _, errs, code := runCLI(t, "vault", "set", "stripe/live", "--key", "STRIPE_SECRET"); code != 0 {
		t.Fatalf("vault set exited %d: %s", code, errs)
	}
	out, errs, code := runCLI(t, "vault", "list")
	if code != 0 {
		t.Fatalf("vault list exited %d: %s", code, errs)
	}
	if !strings.Contains(out, "stripe/live") || !strings.Contains(out, "STRIPE_SECRET") {
		t.Errorf("list output missing the entry:\n%s", out)
	}
	if !strings.Contains(out, "permanent") {
		t.Errorf("list should mark an entry with no ttl as permanent:\n%s", out)
	}
	if strings.Contains(out, cliVaultMarker) {
		t.Fatal("LEAK: vault list printed the value")
	}
}

// The name doubles as the key when it is already a legal env key.
func TestVaultSetInfersTheKeyFromAnUppercaseName(t *testing.T) {
	vaultEnv(t)
	if _, errs, code := runCLI(t, "vault", "set", "STRIPE_SECRET"); code != 0 {
		t.Fatalf("exited %d: %s", code, errs)
	}
	out, _, _ := runCLI(t, "vault", "list")
	if !strings.Contains(out, "STRIPE_SECRET") {
		t.Errorf("list:\n%s", out)
	}
}

// ...and is required when it does not, because no uppercasing of stripe/live is
// defensible.
func TestVaultSetRequiresKeyForANamespacedName(t *testing.T) {
	vaultEnv(t)
	_, errs, code := runCLI(t, "vault", "set", "stripe/live")
	if code != 3 {
		t.Fatalf("exited %d, want 3", code)
	}
	if !strings.Contains(errs, "--key") {
		t.Errorf("the error should name --key: %s", errs)
	}
}

func TestVaultHasExitsOneForAbsentAndPrintsNothing(t *testing.T) {
	vaultEnv(t)
	_, _, _ = runCLI(t, "vault", "set", "A_TOKEN")

	if out, errs, code := runCLI(t, "vault", "has", "A_TOKEN"); code != 0 {
		t.Errorf("has on a live entry exited %d: %s%s", code, out, errs)
	}
	out, errs, code := runCLI(t, "vault", "has", "nope")
	if code != 1 {
		t.Errorf("has on an absent entry exited %d, want 1", code)
	}
	if out != "" || errs != "" {
		t.Errorf("has must print nothing, got out=%q err=%q", out, errs)
	}
}

func TestVaultTTLBeyondThirtyDaysIsRefused(t *testing.T) {
	vaultEnv(t)
	_, errs, code := runCLI(t, "vault", "set", "A_TOKEN", "--ttl", "31d")
	if code != 3 {
		t.Fatalf("exited %d, want 3", code)
	}
	if !strings.Contains(errs, "30d") {
		t.Errorf("the refusal should name the cap: %s", errs)
	}
	if _, _, code := runCLI(t, "vault", "set", "B_TOKEN", "--ttl", "30d"); code != 0 {
		t.Errorf("30d should be accepted, exited %d", code)
	}
}

func TestVaultTTLAcceptsDaysHoursAndMinutes(t *testing.T) {
	for _, s := range []string{"7d", "8h", "30m", "1h30m"} {
		if _, err := query.ParseTTL(s); err != nil {
			t.Errorf("ParseTTL(%q) = %v, want nil", s, err)
		}
	}
	for _, s := range []string{"", "soon", "7days", "-1d", "1w"} {
		if _, err := query.ParseTTL(s); err == nil {
			t.Errorf("ParseTTL(%q) = nil, want an error", s)
		}
	}
}

func TestVaultPushWritesIntoTheProjectEnv(t *testing.T) {
	vaultEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_NAME=demo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _ = runCLI(t, "vault", "set", "stripe/live", "--key", "STRIPE_SECRET")

	out, errs, code := runCLI(t, "vault", "push", "stripe/live", "--to", dir, "--yes")
	if code != 0 {
		t.Fatalf("push exited %d: %s", code, errs)
	}
	if strings.Contains(out+errs, cliVaultMarker) {
		t.Fatal("LEAK: push printed the value")
	}
	body, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(body), "STRIPE_SECRET="+cliVaultMarker) {
		t.Errorf("the value did not reach the destination:\n%s", body)
	}
}

func TestVaultRmRemovesTheEntry(t *testing.T) {
	vaultEnv(t)
	_, _, _ = runCLI(t, "vault", "set", "A_TOKEN")
	if _, errs, code := runCLI(t, "vault", "rm", "A_TOKEN"); code != 0 {
		t.Fatalf("rm exited %d: %s", code, errs)
	}
	if _, _, code := runCLI(t, "vault", "has", "A_TOKEN"); code != 1 {
		t.Error("the entry survived rm")
	}
}

func TestVaultEditRetargetsAKey(t *testing.T) {
	vaultEnv(t)
	_, _, _ = runCLI(t, "vault", "set", "a/b", "--key", "OLD_KEY")
	if _, errs, code := runCLI(t, "vault", "edit", "a/b", "--key", "NEW_KEY"); code != 0 {
		t.Fatalf("edit exited %d: %s", code, errs)
	}
	out, _, _ := runCLI(t, "vault", "list")
	if !strings.Contains(out, "NEW_KEY") || strings.Contains(out, "OLD_KEY") {
		t.Errorf("edit did not retarget:\n%s", out)
	}
}

// --global means ~/.secrets everywhere else in warden and must not acquire a
// second meaning here.
func TestVaultRefusesGlobalOnEverySubcommand(t *testing.T) {
	vaultEnv(t)
	for _, args := range [][]string{
		{"vault", "init", "--global"},
		{"vault", "set", "A_TOKEN", "--global"},
		{"vault", "list", "--global"},
		{"vault", "has", "A_TOKEN", "--global"},
		{"vault", "edit", "A_TOKEN", "--key", "B", "--global"},
		{"vault", "rm", "A_TOKEN", "--global"},
		{"vault", "push", "A_TOKEN", "--to", ".", "--global"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			_, errs, code := runCLI(t, args...)
			if code != 3 {
				t.Errorf("exited %d, want 3", code)
			}
			if !strings.Contains(errs, "--global") {
				t.Errorf("the refusal should name the flag: %s", errs)
			}
		})
	}
}

// The absence of a read path is the design, so it gets a test rather than a
// comment. A future `vault get` would have to delete this to land.
func TestThereIsNoVaultGetCommand(t *testing.T) {
	vaultEnv(t)
	_, _, _ = runCLI(t, "vault", "set", "A_TOKEN")

	for _, name := range []string{"get", "show", "reveal", "cat", "print"} {
		t.Run(name, func(t *testing.T) {
			out, errs, code := runCLI(t, "vault", name, "A_TOKEN")
			if code == 0 {
				t.Fatalf("`vault %s` succeeded — the vault must have no read path", name)
			}
			if strings.Contains(out+errs, cliVaultMarker) {
				t.Fatalf("LEAK: `vault %s` printed the value", name)
			}
		})
	}
}

// rm and push on a machine with no vault should say there is no vault, not that
// there is no such entry — the second sends the user hunting for a name.
func TestVaultRmWithNoVaultNamesTheCreatingCommand(t *testing.T) {
	vaultEnv(t)
	_, errs, code := runCLI(t, "vault", "rm", "anything")
	if code != 3 {
		t.Fatalf("exited %d, want 3", code)
	}
	if !strings.Contains(errs, "no vault yet") || !strings.Contains(errs, "vault set") {
		t.Errorf("the error should say there is no vault and name the command that makes one: %s", errs)
	}
}

func TestVaultListOnAnEmptyVaultSaysSoAndExitsZero(t *testing.T) {
	vaultEnv(t)
	out, errs, code := runCLI(t, "vault", "list")
	if code != 0 {
		t.Fatalf("exited %d: %s", code, errs)
	}
	if strings.TrimSpace(out) == "" && strings.TrimSpace(errs) == "" {
		t.Error("an empty vault should say something rather than printing nothing at all")
	}
}

func TestVaultListJSONHasNoValueField(t *testing.T) {
	vaultEnv(t)
	_, _, _ = runCLI(t, "vault", "set", "A_TOKEN", "--ttl", "8h")
	out, _, code := runCLI(t, "vault", "list", "--json")
	if code != 0 {
		t.Fatalf("exited %d", code)
	}
	if strings.Contains(out, "value") {
		t.Errorf("JSON output must have no value field:\n%s", out)
	}
	for _, want := range []string{"\"name\"", "\"key\"", "\"expires\""} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON missing %s:\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli/ -run TestVault -v`
Expected: FAIL — `unknown command "vault"`, `undefined: query.ParseTTL`.

- [ ] **Step 3: Write `internal/cli/vault.go`**

```go
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/hadefication/warden/internal/prompt"
	"github.com/hadefication/warden/internal/query"
	"github.com/hadefication/warden/internal/write"
)

// homeDir is where the vault lives. The vault is user-global by definition, so
// it takes no --project and refuses --global.
func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// refuseGlobal rejects --global on a vault subcommand. Ignoring the flag would
// be worse than refusing it: --global means ~/.secrets everywhere else in
// warden, and letting it pass silently here would teach it a second meaning.
func refuseGlobal(cmd *cobra.Command) error {
	if global, _ := cmd.Flags().GetBool("global"); global {
		return &ExitError{
			Code: CodeError,
			Msg: "warden: --global does not apply to the vault — the vault is already user-global, " +
				"at " + vaultPathFor(homeDir()),
		}
	}
	return nil
}

func vaultPathFor(home string) string {
	q, err := query.OpenVault(home, SetPrompter)
	if err != nil {
		// Only used for a message; a path is better than nothing.
		return home + "/.warden/vault"
	}
	return q.Path()
}

// vaultErr maps a vault-layer error to an exit code. Exit code 2 is deliberately
// unreachable: it means "refused because the key is secret", and the vault has
// no read path to refuse.
func vaultErr(err error) error {
	switch {
	case errors.Is(err, prompt.ErrCancelled):
		return &ExitError{Code: CodeError, Msg: "warden: cancelled — nothing was written"}
	case errors.Is(err, query.ErrNoVaultEntry) && !vaultFileExists():
		// There is no vault at all, so "no such entry" would send the user
		// looking for a name rather than telling them nothing has been created.
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf(
			"warden: no vault yet — create an entry with: warden vault set <name> --key <KEY>")}
	default:
		return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
	}
}

// vaultFileExists reports whether a vault has ever been written, so an error can
// say "there is no vault" rather than "there is no such entry".
func vaultFileExists() bool {
	q, err := query.OpenVault(homeDir(), SetPrompter)
	return err == nil && q.Exists()
}

func addVaultCommands(root *cobra.Command, out io.Writer) {
	v := &cobra.Command{
		Use:   "vault",
		Short: "store keys warden owns, permanently or with a deadline",
		Long: "A warden-owned store for credentials you reuse across projects.\n\n" +
			"An entry is addressed by a name you choose and records the env key it\n" +
			"lands as, so two projects with different DB_PASSWORD values can coexist.\n\n" +
			"There is no `vault get`. A value leaves the vault only through `vault push`,\n" +
			"which hands it to a destination file without ever rendering it.",
	}

	v.AddCommand(vaultInitCmd(out), vaultSetCmd(out), vaultListCmd(out),
		vaultHasCmd(), vaultEditCmd(out), vaultRmCmd(out), vaultPushCmd(out))
	root.AddCommand(v)
}

func vaultInitCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create the vault, choosing how it is protected at rest",
		Long: "Create an empty vault.\n\n" +
			"By default the master key is stored in the OS keyring, which is what keeps\n" +
			"every other command free of a passphrase prompt. --passphrase derives the\n" +
			"key with Argon2id instead, which is stronger against a local process and\n" +
			"costs a dialog on every command — including from the MCP server, where a\n" +
			"prompt may be unavailable altogether.\n\n" +
			"`vault set` creates a keyring vault on its own, so this is only needed to\n" +
			"choose the passphrase mode.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			passphrase, _ := cmd.Flags().GetBool("passphrase")
			if err := write.InitVault(homeDir(), SetPrompter, passphrase); err != nil {
				return vaultErr(err)
			}
			mode := "keyring"
			if passphrase {
				mode = "passphrase (argon2id)"
			}
			fmt.Fprintf(out, "ok: vault created at %s, protected by %s\n", vaultPathFor(homeDir()), mode)
			return nil
		},
	}
	cmd.Flags().Bool("passphrase", false, "derive the key from a passphrase instead of the OS keyring")
	return cmd
}

func vaultSetCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "store a value under a name, through a prompt",
		Long: "Store a credential in the vault.\n\n" +
			"The value is always typed into a prompt this process owns — there is no\n" +
			"form of this command that takes it as an argument, so it never appears in\n" +
			"shell history or in a caller's output.\n\n" +
			"--key names the environment variable this entry lands as. It may be omitted\n" +
			"when the name is itself a valid env key, so `warden vault set STRIPE_SECRET`\n" +
			"needs nothing further.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			name := args[0]
			key, _ := cmd.Flags().GetString("key")
			if key == "" {
				if !query.LooksLikeEnvKey(name) {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf(
						"warden: %s is not a usable env key, so --key is required "+
							"(for example: warden vault set %s --key STRIPE_SECRET)", name, name)}
				}
				key = name
			}

			var ttl time.Duration
			if raw, _ := cmd.Flags().GetString("ttl"); raw != "" {
				var err error
				if ttl, err = query.ParseTTL(raw); err != nil {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
			}

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Set(name, key, ttl); err != nil {
				return vaultErr(err)
			}
			window := "permanent"
			if ttl > 0 {
				window = "expires in " + ttl.String()
			}
			fmt.Fprintf(out, "ok: %s stored (%s → %s, %s)\n", name, name, key, window)
			return nil
		},
	}
	cmd.Flags().String("key", "", "the env key this entry lands as")
	cmd.Flags().String("ttl", "", "delete the entry after this long (max 30d); omit for permanent")
	return cmd
}

func vaultListCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "list vault entries — names, keys and remaining time, never values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			q, err := query.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			rows := q.List()

			if jsonFlag(cmd) {
				type jsonRow struct {
					Name      string     `json:"name"`
					Key       string     `json:"key"`
					Created   time.Time  `json:"created"`
					Expires   *time.Time `json:"expires,omitempty"`
					Permanent bool       `json:"permanent"`
				}
				payload := make([]jsonRow, 0, len(rows))
				for _, r := range rows {
					jr := jsonRow{Name: r.Name, Key: r.Key, Created: r.Created, Permanent: r.Permanent}
					if !r.Permanent {
						e := r.Expires
						jr.Expires = &e
					}
					payload = append(payload, jr)
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"entries": payload})
			}

			if !q.Exists() {
				fmt.Fprintf(out, "no vault yet — create an entry with: warden vault set <name> --key <KEY>\n")
				return nil
			}
			if len(rows) == 0 {
				fmt.Fprintf(out, "vault is empty (%s)\n", q.Path())
				return nil
			}
			if q.Loosened() {
				fmt.Fprintf(out, "note: %s was more permissive than 0600; the next write corrects it\n", q.Path())
			}
			for _, r := range rows {
				fmt.Fprintf(out, "%-28s → %-24s %s\n", r.Name, r.Key, describeWindow(r))
			}
			return nil
		},
	}
}

// describeWindow renders the remaining time, or "permanent".
func describeWindow(r query.VaultRow) string {
	if r.Permanent {
		return "permanent"
	}
	remaining := time.Until(r.Expires).Round(time.Minute)
	if query.VaultNow != nil {
		remaining = r.Expires.Sub(query.VaultNow()).Round(time.Minute)
	}
	return "expires in " + remaining.String()
}

func vaultHasCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "has <name>",
		Short: "exit 0 if a live entry exists, 1 if not — prints nothing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			q, err := query.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if !q.Has(args[0]) {
				// Empty message: has reports by exit code alone.
				return &ExitError{Code: CodeNo}
			}
			return nil
		},
	}
}

func vaultEditCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name>",
		Short: "change an entry's name, target key, or deadline",
		Long: "Change an entry's metadata. The value is never touched.\n\n" +
			"--ttl none clears a deadline, making the entry permanent. A new --ttl is\n" +
			"measured from now and is capped at 30d like any other.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			o := write.EditOpts{}
			o.NewName, _ = cmd.Flags().GetString("name")
			o.NewKey, _ = cmd.Flags().GetString("key")

			if raw, _ := cmd.Flags().GetString("ttl"); raw != "" {
				var d time.Duration
				if raw != "none" {
					var err error
					if d, err = query.ParseTTL(raw); err != nil {
						return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
					}
				}
				o.TTL = &d
			}
			if o.NewName == "" && o.NewKey == "" && o.TTL == nil {
				return &ExitError{Code: CodeError,
					Msg: "warden: nothing to change — pass --name, --key or --ttl"}
			}

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Edit(args[0], o); err != nil {
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s updated\n", args[0])
			return nil
		},
	}
	cmd.Flags().String("name", "", "rename the entry")
	cmd.Flags().String("key", "", "retarget the env key it lands as")
	cmd.Flags().String("ttl", "", "set a new window (max 30d), or `none` to make it permanent")
	return cmd
}

func vaultRmCmd(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "remove an entry, after you authorise it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			if err := w.Remove(args[0]); err != nil {
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s removed\n", args[0])
			return nil
		},
	}
}

func vaultPushCmd(out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "push <name>",
		Short: "write an entry's value into a project's .env or ~/.secrets",
		Long: "Copy a vault entry into a destination file.\n\n" +
			"This is the only way a value leaves the vault, and it moves a credential\n" +
			"from a file that exists nowhere else into one that may well be committed —\n" +
			"so it asks on your screen first. --yes skips that.\n\n" +
			"--to takes a directory or `global`; omitted, it means the current project.\n" +
			"An already-set destination key is refused unless you pass --force.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := refuseGlobal(cmd); err != nil {
				return err
			}
			to, _ := cmd.Flags().GetString("to")
			dest := scopeFrom(cmd)
			switch to {
			case "":
				// scopeFrom already resolved --project or the cwd.
			case "global":
				dest.Global = true
			default:
				dest.Dir = to
			}

			as, _ := cmd.Flags().GetString("as")
			force, _ := cmd.Flags().GetBool("force")
			yes, _ := cmd.Flags().GetBool("yes")

			w, err := write.OpenVault(homeDir(), SetPrompter)
			if err != nil {
				return vaultErr(err)
			}
			res, err := w.Push(args[0], dest, as, force, yes)
			if err != nil {
				if errors.Is(err, write.ErrDestinationSet) {
					return &ExitError{Code: CodeError, Msg: fmt.Sprintf("warden: %v", err)}
				}
				return vaultErr(err)
			}
			fmt.Fprintf(out, "ok: %s → %s in %s\n", args[0], res.Key, res.Path)
			return nil
		},
	}
	cmd.Flags().String("to", "", "destination: a directory, or `global` for ~/.secrets")
	cmd.Flags().String("as", "", "write it under a different env key")
	cmd.Flags().Bool("force", false, "overwrite a destination key that is already set")
	cmd.Flags().Bool("yes", false, "skip the on-screen confirmation")
	return cmd
}
```

- [ ] **Step 4: Register the family in `internal/cli/cli.go`**

In `newRootCmd`, after `addWriteCommands(root, out)`, add:

```go
	addVaultCommands(root, out)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/cli/ -run TestVault -v`
Expected: PASS. The other cli suites will now fail — that is Step 6.

- [ ] **Step 6: Extend the architecture test**

In `internal/cli/arch_test.go`, replace `TestSurfacePackagesDoNotImportStoreDirectly` with a version that covers all three packages a surface must not reach:

```go
// The safety property depends on internal/query being the only way out of
// internal/store, and internal/write the only way in. The vault adds two more
// packages a surface must not reach: internal/vault holds values, and
// internal/keyring holds the key that unseals them. A surface needs neither.
//
// This checks .Imports rather than .TestImports deliberately — a test file may
// import keyring to install a fake, which is how the vault is exercised without
// touching a real keychain.
func TestSurfacePackagesDoNotImportTheValueLayersDirectly(t *testing.T) {
	forbidden := []string{
		"github.com/hadefication/warden/internal/store",
		"github.com/hadefication/warden/internal/vault",
		"github.com/hadefication/warden/internal/keyring",
	}

	for _, pkg := range []string{
		"github.com/hadefication/warden/internal/cli",
		"github.com/hadefication/warden/internal/mcpserver",
		"github.com/hadefication/warden/cmd/warden",
	} {
		out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for _, imp := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			for _, bad := range forbidden {
				if imp == bad {
					t.Errorf("%s imports %s directly — it must go through internal/query or internal/write",
						pkg, bad)
				}
			}
		}
	}
}
```

**Why the CLI never names `internal/vault`:** the architecture test above forbids
it, so the three things `internal/cli/vault.go` needs from the vault layer cross
the boundary instead of the import doing so. Add them before Step 3 compiles.

Add to `internal/vault/entry.go`:

```go
// dayRE matches a whole number of days, which time.ParseDuration does not
// support and which is the unit a 30-day cap invites people to type.
var dayRE = regexp.MustCompile(`^(\d+)d$`)

// ParseTTL accepts a Go duration, plus Nd for days.
//
// It lives here rather than in a surface package because both the CLI and the
// MCP server parse the same flag, and two copies of a duration parser drift.
func ParseTTL(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if m := dayRE.FindStringSubmatch(s); m != nil {
		days, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration — try 30m, 8h or 7d", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q is not a future window", s)
	}
	return d, nil
}
```

Add `"regexp"` and `"strconv"` to that file's imports.

Add to `internal/query/vault.go`:

```go
// The three things a surface package needs from the vault layer, re-exported so
// it can ask without importing internal/vault — which arch_test.go forbids.

// LooksLikeEnvKey reports whether a name may double as its own env key.
func LooksLikeEnvKey(name string) bool { return vault.LooksLikeEnvKey(name) }

// ParseTTL parses a --ttl value: a Go duration, or Nd for days.
func ParseTTL(s string) (time.Duration, error) { return vault.ParseTTL(s) }

// ErrNoVaultEntry is vault.ErrNoVault, re-exported so a surface can match on it.
var ErrNoVaultEntry = vault.ErrNoVault
```

- [ ] **Step 7: Walk subcommands in the canary and parity tests**

Both tests iterate `root.Commands()`, which sees `vault` as one command and never looks inside it. A vault subcommand could therefore ship with no leak coverage and no parity row. Add this helper to `internal/cli/parity_test.go`:

```go
// commandNames lists every leaf command, descending one level into a family so
// `vault push` is accounted for rather than hidden behind `vault`.
func commandNames(root *cobra.Command) []string {
	var out []string
	for _, c := range root.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		if c.HasSubCommands() {
			for _, sub := range c.Commands() {
				if sub.Name() == "help" || sub.Name() == "completion" {
					continue
				}
				out = append(out, c.Name()+" "+sub.Name())
			}
			continue
		}
		out = append(out, c.Name())
	}
	return out
}
```

Add `"github.com/spf13/cobra"` to that file's imports, then replace both loops:

```go
	for _, name := range commandNames(root) {
		if _, ok := parity[name]; !ok {
			t.Errorf("command %q has no entry in the parity table — add the MCP tool that covers it, "+
				"or map it to \"\" with a comment saying why it is deliberately CLI-only", name)
		}
	}
```

and in `canary_test.go`:

```go
	for _, name := range commandNames(root) {
		if _, ok := covered[name]; !ok {
			t.Errorf("command %q has no entry in the canary table — add one before shipping it. "+
				"If it genuinely cannot be exercised here, map it to nil with a comment saying why.",
				name)
		}
	}
```

- [ ] **Step 8: Add the parity rows**

In `internal/cli/parity_test.go`, add to the `parity` map:

```go
	"vault set":  "vault_request_secret", // the value always comes from a prompt; there is no vault_set
	"vault list": "vault_list",
	"vault has":  "vault_has",
	"vault rm":   "vault_delete",
	"vault push": "vault_push",
	// Deliberately CLI-only. An agent quietly extending a credential's TTL is
	// exactly the operation this surface should not offer.
	"vault edit": "",
	// Deliberately CLI-only. init chooses how the vault is protected at rest —
	// the same class of decision as hook editing the harness's own permissions.
	"vault init": "",
```

And in `toolOwners`, add the request-secret owner beside the existing one:

```go
		// Not commands of their own: the value always arrives through a prompt.
		"env_request_secret":   "set --secret",
		"vault_request_secret": "vault set",
```

Remove `"vault set": "vault_request_secret"` from the map's inverted side by leaving `toolOwners` to overwrite it — the explicit entry above wins, so drop the map row's tool name if the test reports a duplicate owner.

- [ ] **Step 9: Add the canary rows**

In `internal/cli/canary_test.go`, add to `invocations`. These run against the fixture project but drive the **real** `$HOME`-derived vault path, so this table needs the vault redirected — add the setup to `TestNoCommandLeaksASecretValue` first:

```go
	// The vault lives under $HOME, and no test may touch the developer's real
	// one. Redirect it and install a fake keyring for the whole suite.
	t.Setenv("HOME", t.TempDir())
	query.VaultKeyring = &keyring.Fake{}
	t.Cleanup(func() { query.VaultKeyring = nil })
```

with imports for `internal/keyring` and `internal/query`. Then the rows:

```go
		"vault init": {
			{"vault", "init"},
			{"vault", "init"}, // second call is refused: a vault already exists
			{"vault", "init", "--global"},
		},
		"vault set": {
			{"vault", "set", "CANARY_TOKEN"},
			{"vault", "set", "stripe/live", "--key", "STRIPE_SECRET"},
			{"vault", "set", "stripe/live", "--key", "STRIPE_SECRET"}, // replace path
			{"vault", "set", "no/key/given"},
			{"vault", "set", "CANARY_TOKEN", "--ttl", "8h"},
			{"vault", "set", "CANARY_TOKEN", "--ttl", "31d"},
			{"vault", "set", "bad name"},
		},
		"vault list": {
			{"vault", "list"},
			{"vault", "list", "--json"},
		},
		"vault has": {
			{"vault", "has", "CANARY_TOKEN"},
			{"vault", "has", "absent"},
		},
		"vault edit": {
			{"vault", "edit", "CANARY_TOKEN", "--key", "OTHER_TOKEN"},
			{"vault", "edit", "CANARY_TOKEN", "--ttl", "none"},
			{"vault", "edit", "absent", "--key", "X"},
			{"vault", "edit", "CANARY_TOKEN"},
		},
		"vault rm": {
			{"vault", "rm", "CANARY_TOKEN"},
			{"vault", "rm", "absent"},
		},
		"vault push": {
			{"vault", "push", "stripe/live", "--to", "", "--yes"},
			{"vault", "push", "stripe/live", "--to", "", "--yes"}, // now already set
			{"vault", "push", "stripe/live", "--to", "", "--yes", "--force"},
			{"vault", "push", "stripe/live", "--to", "", "--as", "OTHER_KEY", "--yes"},
			{"vault", "push", "absent", "--to", "", "--yes"},
		},
```

The `--to ""` entries reuse the existing substitution that rewrites an empty `--project` value; extend that loop to cover `--to` as well:

```go
				for i, a := range args {
					if (a == "--project" || a == "--to") && i+1 < len(args) && args[i+1] == "" {
						args[i+1] = dir
					}
				}
```

- [ ] **Step 10: Run the whole cli suite**

Run: `go test ./internal/cli/ -v`
Expected: PASS. `TestEveryMCPToolIsAccountedForOnTheCLISurface` still passes because no `vault_*` tool exists yet — the parity rows point forward to Task 6.

- [ ] **Step 11: Full suite**

Run: `CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 12: Commit**

```bash
git add internal/cli internal/query/vault.go
git commit -m "feat(vault): add the vault command family

set, list, has, edit, rm, push and init, with --global refused on every one
of them: it means ~/.secrets everywhere else in warden and must not acquire a
second meaning. set never takes a value argument, so no form of it puts a
credential in shell history.

The canary and parity tests walked only top-level commands, so a vault
subcommand could have shipped with no leak coverage and no parity row. Both
now descend one level, and the canary suite redirects HOME with a fake
keyring so it never touches a real keychain.

LooksLikeEnvKey and ErrNoVault are re-exported through query rather than
imported from internal/vault, because the architecture test forbids a
surface package from reaching the value layer — the right fix is moving the
predicate across the boundary, not weakening the test."
```

---

## Task 6: the `vault_*` MCP tools

**Files:**
- Modify: `internal/mcpserver/server.go` (five tools; extend `ToolNames()`)
- Test: `internal/mcpserver/vault_test.go`

**Interfaces:**
- Consumes: `query.OpenVault`, `query.VaultRow`, `query.ParseTTL`, `write.OpenVault`, `write.EditOpts` (unused here), `write.PushResult`, `write.ErrDestinationSet`.
- Produces: tools `vault_list`, `vault_has`, `vault_request_secret`, `vault_delete`, `vault_push`; `ToolNames()` returns all five in addition to the `env_*` set.

**The two rules this task must not break:**
- **`--yes` is unreachable.** Every `Push` call from here passes `yes: false`, so a push from an agent always confirms on the user's screen. There is no argument that can change it — the field does not exist on the tool's input type.
- **No `vault_set`, no `vault_edit`, no `vault_init`.** The first because no vault entry is public, so a value never legitimately comes from the caller; the other two because they are recorded CLI-only in the parity table.

- [ ] **Step 1: Write the failing tests**

Create `internal/mcpserver/vault_test.go`:

```go
package mcpserver

import (
	"strings"
	"testing"
)

// The parity table in internal/cli names these five. A missing one there fails
// that test; a missing one here fails this test — the pair is what keeps the two
// surfaces from drifting.
func TestToolNamesIncludesTheVaultTools(t *testing.T) {
	have := map[string]bool{}
	for _, n := range ToolNames() {
		have[n] = true
	}
	for _, want := range []string{
		"vault_list", "vault_has", "vault_request_secret", "vault_delete", "vault_push",
	} {
		if !have[want] {
			t.Errorf("ToolNames is missing %q", want)
		}
	}
}

// --yes lets a CLI user skip the confirmation on a push. The MCP surface must not
// be able to: the value crosses into a file that may well be committed, and the
// agent asking is not the party who should authorise that.
func TestNoVaultToolAcceptsAYesArgument(t *testing.T) {
	if strings.Contains(pushArgsFieldNames(), "yes") {
		t.Error("vaultPushArgs has a yes field — the MCP surface must never skip the confirmation")
	}
}

// A tool that mutates the vault without a value must not exist here.
func TestThereIsNoVaultSetOrEditOrInitTool(t *testing.T) {
	for _, n := range ToolNames() {
		switch n {
		case "vault_set", "vault_edit", "vault_init":
			t.Errorf("%q is registered — it is recorded CLI-only in the parity table", n)
		}
	}
}
```

Add this helper to `internal/mcpserver/vault_test.go` so the `--yes` assertion inspects the real type:

```go
import "reflect"

func pushArgsFieldNames() string {
	t := reflect.TypeOf(vaultPushArgs{})
	var names []string
	for i := 0; i < t.NumField(); i++ {
		names = append(names, strings.ToLower(t.Field(i).Name))
	}
	return strings.Join(names, ",")
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/mcpserver/ -run 'TestToolNames|TestNoVault|TestThereIsNo' -v`
Expected: FAIL — `undefined: vaultPushArgs`, and `ToolNames is missing "vault_list"`.

- [ ] **Step 3: Add the argument types to `internal/mcpserver/server.go`**

Beside the existing `setArgs`:

```go
// The vault is user-global, so none of these carry a project or a scope — and
// none of them carries a `yes`. A push from an agent always confirms on the
// user's screen; that is not negotiable through an argument.
type vaultNameArgs struct {
	Name string `json:"name" jsonschema:"the vault entry's name"`
}

type vaultRequestArgs struct {
	Name string `json:"name" jsonschema:"the vault entry's name, e.g. stripe/live"`
	Key  string `json:"key,omitempty" jsonschema:"the env key it lands as; may be omitted when the name is already a valid env key"`
	TTL  string `json:"ttl,omitempty" jsonschema:"delete the entry after this long, e.g. 8h or 7d; maximum 30d; omit for permanent"`
}

type vaultPushArgs struct {
	Name    string `json:"name" jsonschema:"the vault entry to push"`
	Project string `json:"project,omitempty" jsonschema:"destination directory; defaults to the server's working directory"`
	Global  bool   `json:"global,omitempty" jsonschema:"push into ~/.secrets instead of a project .env"`
	As      string `json:"as,omitempty" jsonschema:"write it under a different env key"`
	Force   bool   `json:"force,omitempty" jsonschema:"overwrite a destination key that is already set"`
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}
```

- [ ] **Step 4: Register the five tools in `New`, before the closing `return s`**

```go
	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_list",
		Description: "List the user's vault entries: each entry's name, the env key it lands as, " +
			"when it was stored, and when it expires. Values are never included, and there is no " +
			"tool that reads one — vault_push is how a value reaches a project.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		q, err := query.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		type row struct {
			Name      string `json:"name"`
			Key       string `json:"key"`
			Created   string `json:"created"`
			Expires   string `json:"expires,omitempty"`
			Permanent bool   `json:"permanent"`
		}
		rows := []row{}
		for _, r := range q.List() {
			out := row{Name: r.Name, Key: r.Key, Created: r.Created.UTC().Format(time.RFC3339),
				Permanent: r.Permanent}
			if !r.Permanent {
				out.Expires = r.Expires.UTC().Format(time.RFC3339)
			}
			rows = append(rows, out)
		}
		return nil, rows, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_has",
		Description: "Report whether the vault holds a live entry under this name. An expired entry " +
			"reads as absent. Never reveals a value.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultNameArgs) (*mcp.CallToolResult, any, error) {
		q, err := query.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("%t", q.Has(a.Name))), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_request_secret",
		Description: "Ask the user to type a value into a prompt and store it in the vault under a " +
			"name. The value never passes through this tool — you supply the name, the key it lands " +
			"as, and optionally a ttl. There is no vault_set: no vault entry is public.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultRequestArgs) (*mcp.CallToolResult, any, error) {
		key := a.Key
		if key == "" {
			if !query.LooksLikeEnvKey(a.Name) {
				return errResult(
					"warden: %s is not a usable env key, so key is required", a.Name), nil, nil
			}
			key = a.Name
		}
		var ttl time.Duration
		if a.TTL != "" {
			var err error
			if ttl, err = query.ParseTTL(a.TTL); err != nil {
				return errResult("warden: %v", err), nil, nil
			}
		}
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.Set(a.Name, key, ttl); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was written"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("stored %s (lands as %s)", a.Name, key)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_delete",
		Description: "Remove a vault entry. The user authorises it on their screen first, because " +
			"the value may not be recoverable from anywhere else.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultNameArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		if err := w.Remove(a.Name); err != nil {
			if errors.Is(err, prompt.ErrCancelled) {
				return errResult("warden: cancelled — nothing was removed"), nil, nil
			}
			return errResult("warden: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("removed %s", a.Name)), nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "vault_push",
		Description: "Write a vault entry's value into a project's .env (or ~/.secrets). This is the " +
			"only way a value leaves the vault, and it always asks the user on their screen first — " +
			"it moves a credential into a file that may well be committed. The value is never " +
			"returned to you.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, a vaultPushArgs) (*mcp.CallToolResult, any, error) {
		w, err := write.OpenVault(homeDir(), promptFor())
		if err != nil {
			return errResult("warden: %v", err), nil, nil
		}
		dest := scopeArgs{Project: a.Project, Global: a.Global}.scope()

		// yes is false, always. There is no argument that can change it.
		res, err := w.Push(a.Name, dest, a.As, a.Force, false)
		if err != nil {
			switch {
			case errors.Is(err, prompt.ErrCancelled):
				return errResult("warden: cancelled — nothing was written"), nil, nil
			case errors.Is(err, write.ErrDestinationSet):
				return errResult("warden: %v", err), nil, nil
			default:
				return errResult("warden: %v", err), nil, nil
			}
		}
		return textResult(fmt.Sprintf("pushed %s as %s into %s", a.Name, res.Key, res.Path)), nil, nil
	})
```

Add `"time"` to the file's imports if it is not already there, and add this helper beside `New` so the tools reach the prompter the server was built with:

```go
// promptFor returns the prompter New was given. The vault's passphrase mode and
// every confirmation route through it, so it must be the same channel the env
// tools use rather than a fresh default.
var promptFor = func() prompt.Prompter { return prompt.Default() }
```

In `New`, set it from the parameter as the first statement:

```go
func New(p prompt.Prompter) *mcp.Server {
	promptFor = func() prompt.Prompter { return p }
	s := mcp.NewServer(&mcp.Implementation{Name: "warden", Version: version}, nil)
```

- [ ] **Step 5: Extend `ToolNames()`**

```go
func ToolNames() []string {
	return []string{
		"env_has", "env_list", "env_missing", "env_get", "env_doctor",
		"env_set", "env_request_secret", "env_unset", "env_clear", "env_classify", "env_refs",
		// The vault. There is deliberately no vault_set (no entry is public),
		// no vault_edit and no vault_init (both CLI-only) — internal/cli's
		// parity table records each omission with its reason.
		"vault_list", "vault_has", "vault_request_secret", "vault_delete", "vault_push",
	}
}
```

- [ ] **Step 6: Run the mcpserver tests**

Run: `go test ./internal/mcpserver/ -v`
Expected: PASS. The existing test that compares `ToolNames()` against a live session will fail if a tool name is misspelled in either place — that is the point of it.

- [ ] **Step 7: Run the parity test, which now sees both sides**

Run: `go test ./internal/cli/ -run TestEvery -v`
Expected: PASS. Both directions are now satisfied: every vault subcommand has a parity row, and every `vault_*` tool has an owner.

- [ ] **Step 8: Full suite**

Run: `CGO_ENABLED=0 go build ./... && go vet ./... && go test ./...`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/mcpserver
git commit -m "feat(vault): expose the vault on the MCP surface

Five tools mirroring the env_* set: vault_list, vault_has,
vault_request_secret, vault_delete and vault_push.

vaultPushArgs has no yes field, and a test asserts it never gains one. A
push moves a credential into a file that may well be committed, and the
agent asking is not the party who should authorise that — so every push from
here confirms on the user's screen, with no argument that can skip it.

There is no vault_set, because no vault entry is public and a value therefore
never legitimately comes from the caller. vault_edit and vault_init stay
CLI-only, each recorded in the parity table with its reason."
```

---

## Task 7: documentation and the release-readiness pass

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-18-warden-vault.md` (status line)

- [ ] **Step 1: Add the vault to the README usage block**

In the `## Usage` fenced block, after the `warden hook` line:

```sh
warden vault set stripe/live --key STRIPE_SECRET   # store a key warden owns
warden vault list               # names, target keys, remaining time — never values
warden vault push stripe/live --to ~/Herd/app     # write it into that project's .env
```

- [ ] **Step 2: Add a `## The vault` section after `### The harness hook`**

```markdown
## The vault

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
```

- [ ] **Step 3: Update the MCP surface section of the README**

Replace the tool list sentence with:

```markdown
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
```

- [ ] **Step 4: Update the enforcement section of the README**

In `## How the guarantee is enforced`, extend the architecture-test bullet:

```markdown
- **An architecture test** asserts `internal/cli`, `internal/mcpserver` and
  `cmd/warden` never import `internal/store`, `internal/vault` or
  `internal/keyring` directly — so no surface can reach a raw value without
  passing a classification first, and none can reach the key that unseals the
  vault. A second one holds `internal/refs` to the same line: it deals in key
  names and file paths, and is structurally unable to hold a value.
```

- [ ] **Step 5: Update the design section of the README**

Replace the "Implemented" / "Proposed but not built" sentences with:

```markdown
Later work has one spec per feature in `docs/superpowers/specs/`. Implemented:
`doctor --strict`, `env_doctor` and the parity test, `unset`/`clear`, `refs`,
`hook`, and the `vault`. Proposed but not built: `copy`, `scan`, `run`,
`example --sync`, `--file`/`diff`, rotation age, and the expanded shape rules.
```

- [ ] **Step 6: Mark the spec implemented**

In `docs/superpowers/specs/2026-08-18-warden-vault.md`, change:

```markdown
**Status:** proposed
```

to:

```markdown
**Status:** implemented 2026-08-19
```

- [ ] **Step 7: Run the release-readiness checks**

```bash
CGO_ENABLED=0 go build ./... && go vet ./... && go test ./... && gofmt -l .
```
Expected: all tests PASS and `gofmt -l .` prints nothing. If `goreleaser` is
installed, also run `goreleaser check`.

- [ ] **Step 8: Exercise it by hand once, against a throwaway home**

The suite never touches a real keyring, so one manual run is the only thing that
proves the `security` path works end to end:

```bash
go build -o /tmp/warden-vault-check ./cmd/warden
HOME=$(mktemp -d) /tmp/warden-vault-check vault list
```
Expected: `no vault yet — create an entry with: warden vault set <name> --key <KEY>`.

Then, accepting that this writes a real keychain item you delete afterwards:

```bash
export WARDEN_CHECK_HOME=$(mktemp -d)
HOME=$WARDEN_CHECK_HOME /tmp/warden-vault-check vault set CHECK_TOKEN   # type anything
HOME=$WARDEN_CHECK_HOME /tmp/warden-vault-check vault list
HOME=$WARDEN_CHECK_HOME /tmp/warden-vault-check vault has CHECK_TOKEN; echo "exit=$?"
grep -c 'the value you typed' "$WARDEN_CHECK_HOME/.warden/vault" || echo "value is not in the file — correct"
security delete-generic-password -s warden -a vault-master
rm -rf "$WARDEN_CHECK_HOME" /tmp/warden-vault-check
```
Expected: `list` shows `CHECK_TOKEN → CHECK_TOKEN permanent`, `has` exits 0, the
typed value does not appear in the file, and the cleanup removes both the
keychain item and the temp home.

**Note:** the keychain item is shared by every vault on the machine. Deleting it
at the end is what stops this check from stranding a vault you create later —
and if you already had a real vault before running this, do **not** run the
delete, because that is exactly the unrecoverable state `ErrNoMasterKey` warns
about.

- [ ] **Step 9: Commit**

```bash
git add README.md docs/superpowers/specs/2026-08-18-warden-vault.md
git commit -m "docs: document the vault

Says plainly what encryption at rest buys and what it does not: it defends a
synced backup, a stolen laptop and a cat of the file, but CGO_ENABLED=0 means
keyring access goes through /usr/bin/security, so the ACL protects that tool
rather than warden. Anything that can run security can read the key.

Also records why there is no vault get, why the 30-day cap refuses instead of
clamping, and why five things are CLI-only."
```
