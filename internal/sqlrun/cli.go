package sqlrun

import (
	"context"
	"fmt"
	"strings"
)

// Executor runs a shell command line with the given stdin, locally or remotely.
type Executor interface {
	Run(ctx context.Context, command string, stdin []byte) (stdout, stderr []byte, err error)
	// Describe names the target for error messages, e.g. "local shell" or "root@host:22".
	Describe() string
}

// CLI renders a sqlite3 script, pipes it to Command through Exec and parses
// one output line per Query statement.
type CLI struct {
	Command       string
	Exec          Executor
	BusyTimeoutMS int
}

// ShellQuote quotes s for POSIX sh.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (c *CLI) script(mode Mode, stmts []Statement) (string, int, error) {
	var b strings.Builder
	b.WriteString(".bail on\n")
	fmt.Fprintf(&b, ".timeout %d\n", c.BusyTimeoutMS)
	b.WriteString(".mode list\n")
	b.WriteString("PRAGMA foreign_keys=ON;\n")
	if mode == ModeWrite {
		b.WriteString("BEGIN IMMEDIATE;\n")
	} else {
		b.WriteString("BEGIN DEFERRED;\n")
	}
	queries := 0
	for _, s := range stmts {
		s.SQL = strings.Join(strings.Fields(s.SQL), " ") // collapse layout whitespace; literals never contain raw newlines
		sql, err := inline(s)
		if err != nil {
			return "", 0, err
		}
		if strings.ContainsAny(sql, "\n\r") {
			return "", 0, fmt.Errorf("statement must be single-line: %q", sql)
		}
		b.WriteString(strings.TrimSuffix(strings.TrimSpace(sql), ";"))
		b.WriteString(";\n")
		if s.Query {
			queries++
		}
	}
	b.WriteString("COMMIT;\n")
	return b.String(), queries, nil
}

func (c *CLI) Run(ctx context.Context, mode Mode, stmts []Statement) ([]string, error) {
	script, queries, err := c.script(mode, stmts)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := c.Exec.Run(ctx, c.Command, []byte(script))
	if err != nil {
		return nil, fmt.Errorf("running %q on %s failed: %w: %s", c.Command, c.Exec.Describe(), err, strings.TrimSpace(string(stderr)))
	}
	text := strings.TrimRight(string(stdout), "\r\n")
	var lines []string
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	if len(lines) != queries {
		return nil, fmt.Errorf("expected %d result lines from %q on %s, got %d: %q", queries, c.Command, c.Exec.Describe(), len(lines), text)
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	return lines, nil
}
