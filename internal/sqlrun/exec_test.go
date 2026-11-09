package sqlrun_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

func TestLocalExecCancelKillsChildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := sqlrun.LocalExec{}.Run(ctx, "sleep 20", nil)
	if err == nil {
		t.Fatal("want error after cancellation")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("cancellation took %v", d)
	}
}

func TestSSHHandshakeHonoursContext(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() { // accepts and then says nothing
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	p := 0
	for _, c := range port {
		p = p*10 + int(c-'0')
	}
	_, priv := newTestKey(t)
	ex := sqlrun.SSHExec{Cfg: sqlrun.SSHConfig{Host: host, Port: p, User: "x", PrivateKey: priv, InsecureHost: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := ex.Run(ctx, "true", nil); err == nil {
		t.Fatal("want error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("handshake not interrupted: %v", d)
	}
}

func TestQuoteStringsWithNewlinesStayOnOneLine(t *testing.T) {
	c := &sqlrun.CLI{Command: "true", Exec: sqlrun.LocalExec{}, BusyTimeoutMS: 1}
	_, err := c.Run(context.Background(), sqlrun.ModeRead, []sqlrun.Statement{{SQL: "SELECT ?", Args: []any{strings.Repeat("a\n", 100000)}, Query: true}})
	if err == nil || strings.Contains(err.Error(), "single-line") {
		t.Fatalf("expected a result-count error from the no-op command, got %v", err)
	}
}
