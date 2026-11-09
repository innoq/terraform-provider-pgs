// Package sqlrun executes batches of SQL statements against a SQLite database,
// either in-process (embedded driver) or by piping a script to a sqlite3 CLI,
// locally or over SSH.
package sqlrun

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Mode selects the transaction type used for a batch.
type Mode int

const (
	// ModeRead runs the batch in a deferred transaction; only SELECTs are expected.
	ModeRead Mode = iota
	// ModeWrite runs the batch in BEGIN IMMEDIATE with foreign keys enforced.
	ModeWrite
)

// Statement is one SQL statement using "?" placeholders. SQL must not contain
// a literal "?" other than placeholders. Args may be string, int, int64, bool or nil.
//
// A Query statement must return exactly one row with exactly one text column
// (typically a JSON document); its value is returned by Runner.Run.
type Statement struct {
	SQL   string
	Args  []any
	Query bool
}

// Runner runs a batch of statements atomically (one transaction) and returns
// the single-column result of every Query statement, in order.
type Runner interface {
	Run(ctx context.Context, mode Mode, stmts []Statement) ([]string, error)
}

// inline substitutes the placeholders of s with escaped SQL literals. It is used
// by the CLI runner, which cannot bind parameters.
func inline(s Statement) (string, error) {
	var b strings.Builder
	n := 0
	for _, r := range s.SQL {
		if r != '?' {
			b.WriteRune(r)
			continue
		}
		if n >= len(s.Args) {
			return "", fmt.Errorf("statement has more placeholders than arguments: %s", s.SQL)
		}
		lit, err := literal(s.Args[n])
		if err != nil {
			return "", err
		}
		b.WriteString(lit)
		n++
	}
	if n != len(s.Args) {
		return "", fmt.Errorf("statement has %d placeholders but %d arguments: %s", n, len(s.Args), s.SQL)
	}
	return b.String(), nil
}

func literal(a any) (string, error) {
	switch v := a.(type) {
	case nil:
		return "NULL", nil
	case string:
		return quoteString(v)
	case int:
		return strconv.Itoa(v), nil
	case int64:
		return strconv.FormatInt(v, 10), nil
	case bool:
		if v {
			return "1", nil
		}
		return "0", nil
	default:
		return "", fmt.Errorf("unsupported argument type %T", a)
	}
}

// quoteString renders a SQL string literal. Strings containing line breaks are
// emitted as CAST(X'..' AS TEXT) so that every statement stays on a single line of
// the script, without the expression-depth limit that concatenation would hit.
func quoteString(v string) (string, error) {
	if strings.ContainsRune(v, 0) {
		return "", fmt.Errorf("string argument contains a NUL byte")
	}
	if strings.ContainsAny(v, "\r\n") {
		return "CAST(X'" + hex.EncodeToString([]byte(v)) + "' AS TEXT)", nil
	}
	return "('" + strings.ReplaceAll(v, "'", "''") + "')", nil
}
