package sqlrun

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// LocalExec runs commands through "sh -c" on the machine running the provider.
type LocalExec struct{}

func (LocalExec) Describe() string { return "local shell" }

func (LocalExec) Run(ctx context.Context, command string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	killProcessGroup(cmd) // also stop what sh started (docker, sqlite3, ...)
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}
