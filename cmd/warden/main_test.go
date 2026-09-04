package main

import (
	"os"
	"testing"
)

// Which stdin counts as a caller handing warden a value decides whether the
// user gets the prompt or warden silently reads whatever is on the descriptor.
// Both directions are wrong in a way worth pinning: matching too little turns a
// working pipeline into a dialog nobody expected, and matching too much stores
// the wrong bytes as a credential without asking.
func TestOnlyAPipeCountsAsAValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want bool
	}{
		{"a pipe is the documented channel", os.ModeNamedPipe, true},

		// `./deploy.sh < input.txt` gives every command the script runs a
		// regular-file stdin. Matching it means warden eats the script's input
		// and stores it as the secret, with no prompt and nothing on screen
		// saying the value came from the wrong place. --from-file is the
		// spelling that cannot happen by accident.
		{"a redirected regular file is not", 0, false},

		// These are all "not a terminal" while carrying nothing at all, which
		// is why the negative test is the wrong question to ask here.
		{"a character device such as /dev/null is not", os.ModeCharDevice, false},
		{"a terminal is not", os.ModeCharDevice | os.ModeDevice, false},
		{"a directory is not", os.ModeDir, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := carriesAValue(tc.mode); got != tc.want {
				t.Errorf("carriesAValue(%v) = %v, want %v", tc.mode, got, tc.want)
			}
		})
	}
}
