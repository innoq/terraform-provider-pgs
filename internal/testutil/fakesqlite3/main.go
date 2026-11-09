// Command fakesqlite3 is a minimal stand-in for the sqlite3 CLI used by unit tests
// (the real CLI is exercised by the e2e tests). It understands exactly the script
// dialect rendered by sqlrun.CLI: dot commands, and one SQL statement per line.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite"
)

func fail(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		fail(fmt.Errorf("usage: fakesqlite3 DBFILE"))
	}
	db, err := sql.Open("sqlite", "file:"+os.Args[1]+"?_pragma=busy_timeout(5000)")
	if err != nil {
		fail(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		fail(err)
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ".") {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(line), "SELECT") {
			var v string
			if err := conn.QueryRowContext(context.Background(), line).Scan(&v); err != nil {
				fail(err)
			}
			fmt.Println(v)
			continue
		}
		if _, err := conn.ExecContext(context.Background(), line); err != nil {
			fail(err)
		}
	}
}
