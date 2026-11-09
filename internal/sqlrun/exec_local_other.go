//go:build !unix

package sqlrun

import "os/exec"

func killProcessGroup(*exec.Cmd) {}
