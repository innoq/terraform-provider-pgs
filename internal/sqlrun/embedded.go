package sqlrun

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Embedded runs statements through the in-process modernc SQLite driver. The
// database file must be reachable from the machine running the provider.
type Embedded struct {
	Path          string
	BusyTimeoutMS int
}

func (e *Embedded) dsn() string {
	u := url.URL{Path: e.Path}
	q := url.Values{}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", e.BusyTimeoutMS))
	q.Add("_pragma", "foreign_keys(1)")
	return "file:" + u.EscapedPath() + "?" + q.Encode()
}

func (e *Embedded) Run(ctx context.Context, mode Mode, stmts []Statement) ([]string, error) {
	// Opening a missing file would silently create an empty database.
	if _, err := os.Stat(e.Path); err != nil {
		return nil, fmt.Errorf("pgs database %q: %w", e.Path, err)
	}
	db, err := sql.Open("sqlite", e.dsn())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	begin := "BEGIN DEFERRED"
	if mode == ModeWrite {
		begin = "BEGIN IMMEDIATE"
	}
	if _, err := conn.ExecContext(ctx, begin); err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	rollback := func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }

	var out []string
	for _, s := range stmts {
		if s.Query {
			var v string
			if err := conn.QueryRowContext(ctx, s.SQL, s.Args...).Scan(&v); err != nil {
				rollback()
				return nil, fmt.Errorf("%w (statement: %s)", err, s.SQL)
			}
			out = append(out, v)
			continue
		}
		if _, err := conn.ExecContext(ctx, s.SQL, s.Args...); err != nil {
			rollback()
			return nil, fmt.Errorf("%w (statement: %s)", err, s.SQL)
		}
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		rollback()
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}
