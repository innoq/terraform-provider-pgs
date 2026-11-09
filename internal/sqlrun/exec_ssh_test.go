package sqlrun_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

// startSSHServer runs an in-process SSH server that executes "exec" requests with sh -c.
func startSSHServer(t *testing.T, clientPub ssh.PublicKey) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	_, hpriv, _ := ed25519.GenerateKey(rand.Reader)
	hsigner, err := ssh.NewSignerFromKey(hpriv)
	if err != nil {
		t.Fatal(err)
	}
	return startSSHServerKeys(t, clientPub, hsigner), hsigner.PublicKey()
}

// startSSHServerKeys is startSSHServer with explicit host keys (e.g. both ed25519 and RSA).
func startSSHServerKeys(t *testing.T, clientPub ssh.PublicKey, hostSigners ...ssh.Signer) (addr string) {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if bytes.Equal(k.Marshal(), clientPub.Marshal()) {
			return nil, nil
		}
		return nil, io.EOF
	}}
	for _, hs := range hostSigners {
		cfg.AddHostKey(hs)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go serve(nc, cfg)
		}
	}()
	return l.Addr().String()
}

func serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(r.Payload)
				cmd := exec.Command("sh", "-c", string(r.Payload[4:4+n]))
				cmd.Stdin, cmd.Stdout, cmd.Stderr = ch, ch, ch.Stderr()
				_ = r.Reply(true, nil)
				status := byte(0)
				if err := cmd.Run(); err != nil {
					status = 1
				}
				_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
				ch.Close()
				return
			}
		}()
	}
}

func TestSSHExec(t *testing.T) {
	_, cpriv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(cpriv, "")
	if err != nil {
		t.Fatal(err)
	}
	csigner, _ := ssh.NewSignerFromKey(cpriv)
	addr, hostKey := startSSHServer(t, csigner.PublicKey())
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	ex := sqlrun.SSHExec{Cfg: sqlrun.SSHConfig{
		Host: host, Port: port, User: "test", PrivateKey: pem.EncodeToMemory(block),
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))),
	}}
	out, _, err := ex.Run(t.Context(), "tr a-z A-Z", []byte("hello"))
	if err != nil || string(out) != "HELLO" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, _, err := ex.Run(t.Context(), "exit 3", nil); err == nil {
		t.Fatal("want error for non-zero exit")
	}

	// wrong pinned host key must be rejected
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	op, _ := ssh.NewPublicKey(otherPub)
	bad := ex
	bad.Cfg.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(op)))
	if _, _, err := bad.Run(t.Context(), "true", nil); err == nil {
		t.Fatal("want host key mismatch error")
	}
}

func newTestKey(t *testing.T) (ssh.Signer, []byte) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sg, _ := ssh.NewSignerFromKey(priv)
	return sg, pem.EncodeToMemory(block)
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// A server with several host key types must work when the pin / known_hosts entry is for a type
// that Go would not pick first (here RSA, while ed25519 is also offered).
func TestSSHExecHostKeyAlgorithms(t *testing.T) {
	csigner, cpem := newTestKey(t)
	_, epriv, _ := ed25519.GenerateKey(rand.Reader)
	edSigner, _ := ssh.NewSignerFromKey(epriv)
	rpriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, _ := ssh.NewSignerFromKey(rpriv)
	addr := startSSHServerKeys(t, csigner.PublicKey(), edSigner, rsaSigner)
	host, port := splitAddr(t, addr)
	base := sqlrun.SSHConfig{Host: host, Port: port, User: "test", PrivateKey: cpem}

	// Go offers RSA before ed25519 by default, so each type must work when it is the one on record.
	for name, sg := range map[string]ssh.Signer{"ed25519": edSigner, "rsa": rsaSigner} {
		t.Run("pinned "+name+" host_key", func(t *testing.T) {
			cfg := base
			cfg.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey())))
			if out, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "echo ok", nil); err != nil || string(out) != "ok\n" {
				t.Fatalf("out=%q err=%v", out, err)
			}
		})
		t.Run(name+"-only known_hosts", func(t *testing.T) {
			kh := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{addr}, sg.PublicKey())+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := base
			cfg.KnownHostsFile = kh
			if out, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "echo ok", nil); err != nil || string(out) != "ok\n" {
				t.Fatalf("out=%q err=%v", out, err)
			}
		})
	}
	t.Run("changed key is still rejected", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		osg, _ := ssh.NewSignerFromKey(other)
		kh := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(kh, []byte(knownhosts.Line([]string{addr}, osg.PublicKey())+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := base
		cfg.KnownHostsFile = kh
		if _, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "true", nil); err == nil {
			t.Fatal("want host key mismatch")
		}
	})
}

func TestSSHExecPassphraseKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	csigner, _ := ssh.NewSignerFromKey(priv)
	addr, hostKey := startSSHServer(t, csigner.PublicKey())
	host, port := splitAddr(t, addr)
	cfg := sqlrun.SSHConfig{
		Host: host, Port: port, User: "test", PrivateKey: pem.EncodeToMemory(block),
		HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))),
	}
	if _, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "true", nil); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("want a passphrase hint, got %v", err)
	}
	cfg.Passphrase = []byte("wrong")
	if _, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "true", nil); err == nil {
		t.Fatal("want error for wrong passphrase")
	}
	cfg.Passphrase = []byte("s3cret")
	if out, _, err := (sqlrun.SSHExec{Cfg: cfg}).Run(t.Context(), "echo ok", nil); err != nil || string(out) != "ok\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestExpandHome(t *testing.T) {
	t.Setenv("HOME", "/home/x")
	if got, _ := sqlrun.ExpandHome("~/.ssh/id"); got != "/home/x/.ssh/id" {
		t.Fatalf("got %q", got)
	}
	if got, _ := sqlrun.ExpandHome("/abs/id"); got != "/abs/id" {
		t.Fatalf("got %q", got)
	}
}
