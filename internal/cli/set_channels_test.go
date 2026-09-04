package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sourceFile writes a value file for --from-file to read.
func sourceFile(t *testing.T, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.txt")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetSecretFromFileWritesTheValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	src := sourceFile(t, "hunter2\n")

	out, errw, code := run(t, "set", "--secret", "DB_PASSWORD", "--from-file", src, "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(readEnv(t, dir), "DB_PASSWORD=hunter2") {
		t.Errorf("value not written: %q", readEnv(t, dir))
	}
	if strings.Contains(out+errw, "hunter2") {
		t.Errorf("the value reached the output: %q %q", out, errw)
	}
	if !strings.Contains(out, "creds.txt") {
		t.Errorf("the channel should be named in the confirmation: %q", out)
	}
}

func TestSetFromFileRequiresTheSecretFlag(t *testing.T) {
	// A public value goes on argv where you can read it. --from-file exists so a
	// value can stay out of sight, which is only meaningful for a secret.
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	_, errw, code := run(t, "set", "APP_NAME", "--from-file", sourceFile(t, "x\n"), "--project", dir)
	if code == 0 {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(errw, "--secret") {
		t.Errorf("the refusal should point at --secret: %q", errw)
	}
}

func TestSetFromFileRefusesWardensOwnFiles(t *testing.T) {
	// Copying a key out of a file warden already manages is never provisioning.
	// It is the one shape that looks like exfiltration rather than setup.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	_, errw, code := run(t, "set", "--secret", "K", "--from-file",
		filepath.Join(dir, ".env"), "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errw, "warden") {
		t.Errorf("expected an explanation: %q", errw)
	}
}

func TestSetSecretGenerateWritesAFreshValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "set", "--secret", "API_KEY", "--generate", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	body := readEnv(t, dir)
	if !strings.Contains(body, "API_KEY=") {
		t.Fatalf("value not written: %q", body)
	}
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, "API_KEY="); ok {
			if len(v) != 64 {
				t.Errorf("generated value is %d chars, want 64", len(v))
			}
			if strings.Contains(out, v) {
				t.Error("the generated value was printed — nobody should learn it from warden")
			}
		}
	}
	if !strings.Contains(out, "generated") {
		t.Errorf("the channel should be named: %q", out)
	}
}

func TestSetSecretChannelsAreMutuallyExclusive(t *testing.T) {
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	_, errw, code := run(t, "set", "--secret", "K",
		"--generate", "--from-file", sourceFile(t, "x\n"), "--project", dir)
	if code == 0 {
		t.Fatal("want a refusal when two value sources are given")
	}
	if !strings.Contains(errw, "one") && !strings.Contains(errw, "exclusive") {
		t.Errorf("expected an explanation naming the conflict: %q", errw)
	}
}

func TestSetSecretFromStdin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	withStdin(t, "hunter2\n")

	out, errw, code := run(t, "set", "--secret", "DB_PASSWORD", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(readEnv(t, dir), "DB_PASSWORD=hunter2") {
		t.Errorf("value not written: %q", readEnv(t, dir))
	}
	if !strings.Contains(out, "stdin") {
		t.Errorf("the weakest channel must be named in the output: %q", out)
	}
}

func TestSetExposedWritesAndWarns(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "set", "--exposed", "CF_API_TOKEN", "abc123", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(readEnv(t, dir), "CF_API_TOKEN=abc123") {
		t.Errorf("value not written: %q", readEnv(t, dir))
	}
	if !strings.Contains(strings.ToLower(out+errw), "rotate") {
		t.Errorf("an exposed write must say the value is burned: %q %q", out, errw)
	}
}

func TestSetExposedKeepsTheKeyUnreadable(t *testing.T) {
	// --exposed describes how the value got in, not who may read it.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	if _, errw, code := run(t, "set", "--exposed", "CF_API_TOKEN", "abc123", "--project", dir); code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	out, _, code := run(t, "get", "CF_API_TOKEN", "--project", dir)
	if code != 2 {
		t.Errorf("get code = %d, want 2 (still refused)", code)
	}
	if strings.Contains(out, "abc123") {
		t.Error("get printed a value that --exposed never made public")
	}
}

func TestSetExposedRefusesTheSafeChannels(t *testing.T) {
	// Those channels expose nothing, so the flag would be a false statement.
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})
	for _, extra := range [][]string{
		{"--secret", "--generate"},
		{"--secret", "--from-file", sourceFile(t, "x\n")},
	} {
		args := append([]string{"set", "--exposed", "K"}, extra...)
		args = append(args, "--project", dir)
		if _, _, code := run(t, args...); code == 0 {
			t.Errorf("%v: want a refusal", extra)
		}
	}
}

func TestSetPublicProvisionsANewKeyInOneStep(t *testing.T) {
	// The friction this removes: a key that is secret only by the fail-closed
	// default used to need `classify --set public` first, on a key that did not
	// exist yet.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "APP_NAME=Warden\n"})

	out, errw, code := run(t, "set", "--public", "CF_GROUP_ID", "abc123", "--project", dir)
	if code != 0 {
		t.Fatalf("code = %d: %s", code, errw)
	}
	if !strings.Contains(readEnv(t, dir), "CF_GROUP_ID=abc123") {
		t.Errorf("value not written: %q", readEnv(t, dir))
	}
	if !strings.Contains(out, "public") {
		t.Errorf("the confirmation should say the key is now public: %q", out)
	}

	// And it is genuinely readable now, which is the whole point.
	if _, _, code := run(t, "get", "CF_GROUP_ID", "--project", dir); code != 0 {
		t.Errorf("get code = %d, want 0", code)
	}
}

func TestSetPublicRefusesAKeyThatAlreadyHoldsAValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := project(t, map[string]string{".env": "CF_API_TOKEN=live-value\n"})

	out, errw, code := run(t, "set", "--public", "CF_API_TOKEN", "new", "--project", dir)
	if code != 2 {
		t.Errorf("code = %d, want 2", code)
	}
	if !strings.Contains(errw, "classify") {
		t.Errorf("the refusal should point at the ceremony: %q", errw)
	}
	if strings.Contains(out+errw, "live-value") {
		t.Error("the refusal echoed the stored value")
	}
	if got := readEnv(t, dir); got != "CF_API_TOKEN=live-value\n" {
		t.Errorf("the file changed despite the refusal: %q", got)
	}
}

// withStdin installs a piped standard input for the duration of a test. The
// default is nil — no stdin channel — so every other test keeps the prompter.
func withStdin(t *testing.T, raw string) {
	t.Helper()
	prev := SetStdin
	SetStdin = strings.NewReader(raw)
	t.Cleanup(func() { SetStdin = prev })
}
