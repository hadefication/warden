package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const canary = "cnry-9f3a1d-do-not-leak"

func TestSecretRedactsUnderEveryVerb(t *testing.T) {
	s := Secret(canary)
	for _, format := range []string{"%v", "%s", "%q", "%+v", "%#v", "%d", "%x"} {
		got := fmt.Sprintf(format, s)
		if strings.Contains(got, canary) {
			t.Errorf("format %s leaked the value: %s", format, got)
		}
	}
}

func TestSecretRedactsWhenStringed(t *testing.T) {
	if got := Secret(canary).String(); strings.Contains(got, canary) {
		t.Errorf("String() leaked: %s", got)
	}
}

func TestSecretRedactsInJSON(t *testing.T) {
	b, err := json.Marshal(struct {
		Value Secret `json:"value"`
	}{Secret(canary)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), canary) {
		t.Errorf("json.Marshal leaked: %s", b)
	}
}

func TestSecretInsideMapAndSliceStillRedacts(t *testing.T) {
	b, _ := json.Marshal(map[string]Secret{"k": Secret(canary)})
	if strings.Contains(string(b), canary) {
		t.Errorf("map marshal leaked: %s", b)
	}
	got := fmt.Sprintf("%v", []Secret{Secret(canary)})
	if strings.Contains(got, canary) {
		t.Errorf("slice format leaked: %s", got)
	}
}

func TestExposeReturnsTheRealValue(t *testing.T) {
	if got := Secret(canary).Expose(); got != canary {
		t.Errorf("Expose() = %q, want the original value", got)
	}
}

func TestIsSet(t *testing.T) {
	if Secret("").IsSet() {
		t.Error("empty Secret must report IsSet() == false")
	}
	if !Secret("x").IsSet() {
		t.Error("non-empty Secret must report IsSet() == true")
	}
}
