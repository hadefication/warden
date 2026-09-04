package prompt

import (
	"errors"
	"regexp"
	"testing"
)

var hexOnly = regexp.MustCompile(`^[0-9a-f]+$`)

func TestGeneratedProducesHexOfTheRequestedByteLength(t *testing.T) {
	got, err := Generated{Bytes: 32}.AskSecret("API_KEY", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Expose()) != 64 {
		t.Errorf("got %d chars, want 64 (32 bytes hex-encoded)", len(got.Expose()))
	}
	if !hexOnly.MatchString(got.Expose()) {
		t.Error("value should be lowercase hex, so it survives .env quoting untouched")
	}
}

func TestGeneratedDefaultsTo32Bytes(t *testing.T) {
	got, err := Generated{}.AskSecret("API_KEY", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Expose()) != 64 {
		t.Errorf("got %d chars, want the 32-byte default", len(got.Expose()))
	}
}

func TestGeneratedValuesDiffer(t *testing.T) {
	// The one property that makes this channel worth having. A constant would
	// pass every other test in this file.
	a, err := Generated{}.AskSecret("K", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generated{}.AskSecret("K", "/tmp/.env")
	if err != nil {
		t.Fatal(err)
	}
	if a.Expose() == b.Expose() {
		t.Fatal("two generated values were identical — the source is not random")
	}
}

func TestGeneratedRefusesATrivialLength(t *testing.T) {
	// A flag that can produce an 8-bit secret is a footgun wearing a helpful hat.
	_, err := Generated{Bytes: 4}.AskSecret("K", "/tmp/.env")
	if !errors.Is(err, ErrTooShort) {
		t.Fatalf("err = %v, want ErrTooShort", err)
	}
}

func TestGeneratedAcceptsTheMinimumLength(t *testing.T) {
	if _, err := (Generated{Bytes: MinGeneratedBytes}).AskSecret("K", "/tmp/.env"); err != nil {
		t.Fatalf("the documented minimum must be accepted: %v", err)
	}
}
