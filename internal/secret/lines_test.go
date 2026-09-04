package secret

import "testing"

// Lines exists so a caller can learn how many lines a value spans without
// calling Expose. Counting is the whole answer to "is this multi-line?", and
// answering it here keeps the Expose budget where it is.
func TestLinesCountsWithoutExposing(t *testing.T) {
	cases := []struct {
		name string
		in   Secret
		want int
	}{
		{"empty", "", 0},
		{"single line", "hunter2", 1},
		{"two lines", "a\nb", 2},
		{"trailing newline counts the empty last line", "a\n", 2},
		{"PEM block", "-----BEGIN-----\nabc\n-----END-----", 3},
		{"CRLF", "a\r\nb", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.Lines(); got != tc.want {
				t.Errorf("Lines() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLinesDoesNotLeakThroughItsResult(t *testing.T) {
	// A count is not a value. This is the property that makes Lines safe to call
	// from a surface package.
	if got := Secret(canary).Lines(); got != 1 {
		t.Errorf("Lines() = %d, want 1", got)
	}
}
