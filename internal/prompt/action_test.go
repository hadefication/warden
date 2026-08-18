package prompt

import (
	"errors"
	"strings"
	"testing"
)

func TestActionDialogNamesTheKeyAndTheFileAndDefaultsToCancel(t *testing.T) {
	s := buildActionScript("remove", "GH_TOKEN", "/tmp/.env", 60)
	if strings.Contains(s, "default answer") {
		t.Error("removal is not a disclosure — it must not demand retyping")
	}
	if !strings.Contains(s, `default button "Cancel"`) {
		t.Error("Return must not authorise a destructive change")
	}
	if !strings.Contains(s, "GH_TOKEN") {
		t.Error("the dialog must name the key")
	}
	if !strings.Contains(s, "/tmp/.env") {
		t.Error("the dialog must name the file, so the user sees what they are authorising")
	}
	if !strings.Contains(s, "giving up after 60") {
		t.Error("the dialog must time out")
	}
}

func TestActionDialogSaysWhichActionItIs(t *testing.T) {
	if !strings.Contains(strings.ToLower(buildActionScript("remove", "K", "/tmp/.env", 60)), "remove") {
		t.Error("the remove dialog must say it removes")
	}
	cleared := strings.ToLower(buildActionScript("clear", "K", "/tmp/.env", 60))
	if !strings.Contains(cleared, "clear") || strings.Contains(cleared, "remove") {
		t.Error("clear and remove must be distinguishable in the dialog")
	}
}

func TestRefusingActionNamesTheExactCommandToRun(t *testing.T) {
	err := Refusing{}.ConfirmAction("remove", "GH_TOKEN", "/tmp/.env")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "warden unset GH_TOKEN") {
		t.Errorf("error should quote the command to run, got: %v", err)
	}
	err = Refusing{}.ConfirmAction("clear", "GH_TOKEN", "/tmp/.env")
	if !strings.Contains(err.Error(), "warden clear GH_TOKEN") {
		t.Errorf("error should quote the clear command, got: %v", err)
	}
}

func TestFakeActionApprovesAndCanDecline(t *testing.T) {
	if err := (Fake{}).ConfirmAction("remove", "K", "/tmp/.env"); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if err := (Fake{ConfirmErr: ErrCancelled}).ConfirmAction("remove", "K", "/tmp/.env"); !errors.Is(err, ErrCancelled) {
		t.Errorf("err = %v, want ErrCancelled", err)
	}
}

func TestFakeReportsWhenItWasAskedToAuthoriseAnAction(t *testing.T) {
	var gotAction, gotKey string
	p := Fake{OnAction: func(action, key, _ string) { gotAction, gotKey = action, key }}
	_ = p.ConfirmAction("remove", "GH_TOKEN", "/tmp/.env")
	if gotAction != "remove" || gotKey != "GH_TOKEN" {
		t.Errorf("OnAction saw (%q, %q), want (remove, GH_TOKEN)", gotAction, gotKey)
	}
}

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
