package prompt

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// confirmButton is the affirmative button on the plain confirmation dialog.
// Cancel is the default, so pressing Return declines.
const confirmButton = "Authorise"

// checkRetyped compares what the user typed against the key they were asked to
// retype. Every outcome other than an exact match is a refusal — a typo and a
// deliberate decline are the same answer, and guessing which was meant would
// mean acting on something the user did not confirm.
//
// The error never reports what was typed. The caller is frequently an agent, and
// "you typed BAR_KEY, expected FOO_KEY" is a hint it has no business receiving.
func checkRetyped(raw, key string) error {
	typed := strings.TrimSpace(raw)
	if typed == timeoutSentinel {
		return fmt.Errorf("dialog timed out: %w", ErrCancelled)
	}
	if typed != key {
		return fmt.Errorf("confirmation did not match %s: %w", key, ErrCancelled)
	}
	return nil
}

// buildConfirmScript renders the AppleScript for an authorisation dialog.
//
// The retype variant uses a visible answer field: the user is checking their own
// typing against a key name, which is not secret, and hiding it would defeat the
// point. The plain variant is buttons only, with Cancel as the default button so
// a reflexive Return declines rather than authorises.
func buildConfirmScript(class, key, path string, seconds int, retypeKey bool) string {
	msg := fmt.Sprintf("Record %s as %s.\n\nThis writes to:\n%s", key, class, path)
	title := applescriptString("warden — " + key)

	if retypeKey {
		msg += fmt.Sprintf(
			"\n\nwarden will print this key's value once it is public.\n\nType %s to confirm:", key)
		return fmt.Sprintf(
			"set r to display dialog %s with title %s default answer \"\" giving up after %d\n"+
				"if gave up of r then\n  return %s\nend if\n"+
				"return text returned of r",
			applescriptString(msg), title, seconds, applescriptString(timeoutSentinel))
	}
	return fmt.Sprintf(
		"set r to display dialog %s with title %s buttons {%s, %s} default button %s giving up after %d\n"+
			"if gave up of r then\n  return %s\nend if\n"+
			"return button returned of r",
		applescriptString(msg), title,
		applescriptString("Cancel"), applescriptString(confirmButton), applescriptString("Cancel"),
		seconds, applescriptString(timeoutSentinel))
}

// actionSentence renders what the user is being asked to authorise. The wording
// is deliberately concrete about the consequence: "remove" is not recoverable
// from warden, and a dialog that only said "modify" would undersell that.
func actionSentence(action, key string) string {
	switch action {
	case "clear":
		return fmt.Sprintf("Clear the value of %s, leaving the key declared and empty.", key)
	default:
		return fmt.Sprintf("Remove %s. Its value will be gone from this file.", key)
	}
}

// actionCommand names the command the user can run themselves when there is no
// channel to ask them through.
func actionCommand(action, key string) string {
	if action == "clear" {
		return "warden clear " + key
	}
	return "warden unset " + key
}

// buildActionScript renders the AppleScript for a destructive-change dialog.
// Buttons only, with Cancel as the default: a reflexive Return must decline.
func buildActionScript(action, key, path string, seconds int) string {
	msg := fmt.Sprintf("%s\n\nThis writes to:\n%s", actionSentence(action, key), path)
	return fmt.Sprintf(
		"set r to display dialog %s with title %s buttons {%s, %s} default button %s giving up after %d\n"+
			"if gave up of r then\n  return %s\nend if\n"+
			"return button returned of r",
		applescriptString(msg), applescriptString("warden — "+key),
		applescriptString("Cancel"), applescriptString(confirmButton), applescriptString("Cancel"),
		seconds, applescriptString(timeoutSentinel))
}

// ConfirmAction shows the destructive-change dialog.
func (o Osascript) ConfirmAction(action, key, path string) error {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	out, err := exec.Command("osascript", "-e",
		buildActionScript(action, key, path, int(timeout.Seconds()))).Output()
	if err != nil {
		return ErrCancelled
	}
	if strings.TrimSpace(string(out)) != confirmButton {
		return ErrCancelled
	}
	return nil
}

// ConfirmAction asks on the controlling terminal.
func (TTY) ConfirmAction(action, key, path string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer tty.Close()

	fmt.Fprintf(tty, "warden: %s\n  target: %s\n  proceed? [y/N]: ", actionSentence(action, key), path)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return ErrCancelled
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return ErrCancelled
}

// ConfirmAction reports that there is no channel to ask through.
func (Refusing) ConfirmAction(action, key, path string) error {
	return fmt.Errorf("%w — run this yourself in a terminal: %s (target: %s)",
		ErrUnavailable, actionCommand(action, key), path)
}

// ConfirmAction approves unless ConfirmErr is set.
func (f Fake) ConfirmAction(action, key, path string) error {
	if f.OnAction != nil {
		f.OnAction(action, key, path)
	}
	return f.ConfirmErr
}

// Confirm shows the authorisation dialog and reports whether the user approved.
func (o Osascript) Confirm(class, key, path string, retypeKey bool) error {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	script := buildConfirmScript(class, key, path, int(timeout.Seconds()), retypeKey)
	out, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		// Pressing Cancel makes osascript exit non-zero.
		return ErrCancelled
	}
	if retypeKey {
		return checkRetyped(string(out), key)
	}
	if strings.TrimSpace(string(out)) != confirmButton {
		return ErrCancelled
	}
	return nil
}

// Confirm asks on the controlling terminal. Unlike AskSecret it leaves echo on:
// the answer is a key name or a yes, never a credential.
func (TTY) Confirm(class, key, path string, retypeKey bool) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer tty.Close()

	fmt.Fprintf(tty, "warden: record %s as %s\n  target: %s\n", key, class, path)
	r := bufio.NewReader(tty)

	if retypeKey {
		fmt.Fprintf(tty, "  warden will print this key's value once it is public.\n  type %s to confirm: ", key)
		line, err := r.ReadString('\n')
		if err != nil {
			return ErrCancelled
		}
		return checkRetyped(line, key)
	}

	fmt.Fprint(tty, "  proceed? [y/N]: ")
	line, err := r.ReadString('\n')
	if err != nil {
		return ErrCancelled
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return ErrCancelled
}

// Confirm reports that there is no channel to ask through, and names the command
// the user should run themselves.
func (Refusing) Confirm(class, key, path string, _ bool) error {
	return fmt.Errorf(
		"%w — run this yourself in a terminal: warden classify %s --set %s (target: %s)",
		ErrUnavailable, key, class, path)
}

// Confirm approves unless ConfirmErr is set, and signals OnConfirm so a test can
// assert whether the user was asked at all.
func (f Fake) Confirm(class, key, path string, retypeKey bool) error {
	if f.OnConfirm != nil {
		f.OnConfirm(class, key, path, retypeKey)
	}
	return f.ConfirmErr
}
