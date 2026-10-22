// Package notify shows a desktop notification for a new key request.
package notify

import (
	"os/exec"
	"runtime"
)

// Send shows a notification. Title and message may contain agent-provided
// text, so they are passed as program arguments, never spliced into a
// script, to rule out AppleScript injection. Failures are ignored: the
// dashboard and terminal still show the request.
func Send(title, message string) {
	switch runtime.GOOS {
	case "darwin":
		run(exec.Command("osascript",
			"-e", "on run argv",
			"-e", `display notification (item 2 of argv) with title (item 1 of argv) sound name "Ping"`,
			"-e", "end run",
			title, message))
	case "linux":
		if path, err := exec.LookPath("notify-send"); err == nil {
			run(exec.Command(path, "--", title, message))
		}
	}
}

// run executes cmd in the background and reaps it.
func run(cmd *exec.Cmd) { go func() { _ = cmd.Run() }() }
