// Command pgs-sqlhelper runs a batch of SQL statements against a SQLite database.
// The provider uploads it to the host that holds the pgs database, so that host needs
// no sqlite3 installation. Request on stdin, response on stdout (both JSON).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

func main() {
	resp := run()
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	if resp.Error != "" {
		os.Exit(1)
	}
}

func run() sqlrun.Response {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		return sqlrun.Response{Error: err.Error()}
	}
	var req sqlrun.Request
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return sqlrun.Response{Error: "bad request: " + err.Error()}
	}
	stmts := make([]sqlrun.Statement, len(req.Statements))
	for i, s := range req.Statements {
		args := make([]any, len(s.Args))
		for j, a := range s.Args {
			if n, ok := a.(json.Number); ok {
				v, err := n.Int64()
				if err != nil {
					return sqlrun.Response{Error: fmt.Sprintf("bad number argument %q", n)}
				}
				a = v
			}
			args[j] = a
		}
		stmts[i] = sqlrun.Statement{SQL: s.SQL, Args: args, Query: s.Query}
	}
	mode := sqlrun.ModeRead
	if req.Write {
		mode = sqlrun.ModeWrite
	}
	e := &sqlrun.Embedded{Path: req.Path, BusyTimeoutMS: req.BusyTimeoutMS}
	out, err := e.Run(context.Background(), mode, stmts)
	if err != nil {
		return sqlrun.Response{Error: err.Error()}
	}
	return sqlrun.Response{Results: out}
}
