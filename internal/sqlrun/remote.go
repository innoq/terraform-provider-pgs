package sqlrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Remote runs batches on an SSH host through an uploaded helper binary (cmd/pgs-sqlhelper,
// pure Go SQLite), so the host needs neither sqlite3 nor a container. Only sh, cat, chmod,
// mv and uname are used on the host.
type Remote struct {
	SSH           SSHExec
	Path          string // database path on the host
	BusyTimeoutMS int
	// HelperDir is where the helper is stored on the host; default: the login directory.
	HelperDir string
	// Become runs the helper as this user through `sudo -n -u` (needs passwordless sudo).
	// The helper file must then be readable and executable by that user: use a HelperDir
	// such as /tmp, not a private home directory.
	Become string
	// Binary returns the helper for the host's OS/arch (e.g. helperbin.Get).
	Binary func(goos, goarch string) ([]byte, error)

	mu     sync.Mutex
	helper string // remote command, once ensured
}

func (r *Remote) ensureHelper(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.helper != "" {
		return r.helper, nil
	}
	out, errb, err := r.SSH.Run(ctx, "uname -sm", nil)
	if err != nil {
		return "", fmt.Errorf("uname on %s failed: %w: %s", r.SSH.Describe(), err, strings.TrimSpace(string(errb)))
	}
	f := strings.Fields(string(out))
	if len(f) != 2 || f[0] != "Linux" {
		return "", fmt.Errorf("unsupported remote platform %q on %s (only Linux is supported)", strings.TrimSpace(string(out)), r.SSH.Describe())
	}
	var arch string
	switch f[1] {
	case "x86_64", "amd64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	default:
		return "", fmt.Errorf("unsupported remote architecture %q on %s", f[1], r.SSH.Describe())
	}
	bin, err := r.Binary("linux", arch)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(bin)
	name := ".pgs-sqlhelper-" + hex.EncodeToString(sum[:])[:16]
	dir := `"$HOME"`
	if r.HelperDir != "" {
		dir = ShellQuote(r.HelperDir)
	}
	target := dir + "/" + name
	mode := "700"
	if r.Become != "" {
		mode = "755" // another user must execute it
	}
	// Upload only when missing, in a separate command: a command that ignores stdin would make
	// the session fail with EOF while the binary is still being written. Write to a temp file and
	// rename so a half-written helper is never run.
	if _, _, err := r.SSH.Run(ctx, "[ -x "+target+" ]", nil); err != nil {
		cmd := fmt.Sprintf(`set -e; t=%s; cat > "$t.$$" && chmod %s "$t.$$" && mv "$t.$$" "$t"`, target, mode)
		if _, errb, err := r.SSH.Run(ctx, cmd, bin); err != nil {
			return "", fmt.Errorf("uploading sqlite helper to %s failed: %w: %s", r.SSH.Describe(), err, strings.TrimSpace(string(errb)))
		}
	}
	r.helper = target
	return r.helper, nil
}

func (r *Remote) Run(ctx context.Context, mode Mode, stmts []Statement) ([]string, error) {
	helper, err := r.ensureHelper(ctx)
	if err != nil {
		return nil, err
	}
	req := Request{Path: r.Path, BusyTimeoutMS: r.BusyTimeoutMS, Write: mode == ModeWrite}
	for _, s := range stmts {
		req.Statements = append(req.Statements, RequestStmt{SQL: s.SQL, Args: s.Args, Query: s.Query})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	command := helper
	if r.Become != "" {
		command = "sudo -n -u " + ShellQuote(r.Become) + " " + helper
	}
	stdout, stderr, runErr := r.SSH.Run(ctx, command, body)
	var resp Response
	if err := json.NewDecoder(bytes.NewReader(stdout)).Decode(&resp); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("sqlite helper on %s failed: %w: %s", r.SSH.Describe(), runErr, strings.TrimSpace(string(stderr)))
		}
		return nil, fmt.Errorf("bad response from sqlite helper on %s: %w", r.SSH.Describe(), err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("on %s: %s", r.SSH.Describe(), resp.Error)
	}
	return resp.Results, nil
}
