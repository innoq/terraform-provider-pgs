// Package testutil holds helpers shared by unit tests.
package testutil

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	_ "modernc.org/sqlite"
)

var (
	buildOnce sync.Once
	fakePath  string
	buildErr  error
)

// FakeSQLite3 builds (once per test binary) the fakesqlite3 helper and returns its path.
func FakeSQLite3(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fakesqlite3")
		if err != nil {
			buildErr = err
			return
		}
		fakePath = filepath.Join(dir, "sqlite3")
		out, err := exec.Command("go", "build", "-o", fakePath, "github.com/innoq/terraform-provider-pgs/internal/testutil/fakesqlite3").CombinedOutput()
		if err != nil {
			buildErr = &buildError{err, string(out)}
		}
	})
	if buildErr != nil {
		t.Fatalf("building fakesqlite3: %v", buildErr)
	}
	return fakePath
}

type buildError struct {
	err error
	out string
}

func (e *buildError) Error() string { return e.err.Error() + ": " + e.out }

// NewPgsDB creates an empty pgs database from schemaFile (as pgs does on first start) and returns its path.
func NewPgsDB(t *testing.T, schemaFile string) string {
	t.Helper()
	schema, err := os.ReadFile(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pgs.sqlite3")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
		t.Fatal(err)
	}
	return path
}
