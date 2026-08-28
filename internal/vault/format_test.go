package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/webteractive/warden/internal/secret"
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
