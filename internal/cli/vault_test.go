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
