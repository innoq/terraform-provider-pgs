package sqlrun_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

func TestRemoteHelper(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs a linux host")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper")
	if out, err := exec.Command("go", "build", "-o", helper, "../../cmd/pgs-sqlhelper").CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}

	signer, priv := newTestKey(t)
	addr, hostKey := startSSHServer(t, signer.PublicKey())
	host, port := splitAddr(t, addr)
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	r := &sqlrun.Remote{
		SSH: sqlrun.SSHExec{Cfg: sqlrun.SSHConfig{
			Host: host, Port: port, User: "test", PrivateKey: priv,
			HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))),
		}},
		Path:          filepath.Join(dir, "db.sqlite3"),
		BusyTimeoutMS: 1000,
		Binary:        func(_, _ string) ([]byte, error) { return bin, nil },
	}
	// The embedded driver refuses to create a missing database file.
	if err := os.WriteFile(r.Path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = r.Run(ctx, sqlrun.ModeWrite, []sqlrun.Statement{
		{SQL: "CREATE TABLE t (id INTEGER, s TEXT)"},
		{SQL: "INSERT INTO t VALUES (?, ?)", Args: []any{int64(1 << 40), "a'b\nc"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Run(ctx, sqlrun.ModeRead, []sqlrun.Statement{{SQL: "SELECT json_object('id', id, 's', s) FROM t", Query: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != `{"id":1099511627776,"s":"a'b\nc"}` {
		t.Fatalf("got %q", out)
	}
	if _, err := r.Run(ctx, sqlrun.ModeRead, []sqlrun.Statement{{SQL: "SELECT * FROM nope", Query: true}}); err == nil || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("want sqlite error, got %v", err)
	}
	// A fresh runner (new provider process) finds the helper already uploaded.
	if _, err := (&sqlrun.Remote{SSH: r.SSH, Path: r.Path, BusyTimeoutMS: 1000, Binary: r.Binary}).Run(ctx, sqlrun.ModeRead, []sqlrun.Statement{{SQL: "SELECT 1", Query: true}}); err != nil {
		t.Fatal(err)
	}
}
