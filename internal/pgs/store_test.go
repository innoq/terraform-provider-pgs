package pgs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/innoq/terraform-provider-pgs/internal/pgs"
	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
	"github.com/innoq/terraform-provider-pgs/internal/testutil"
)

func newKey(t *testing.T, comment string) pgs.KeyInput {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	pk, err := pgs.ParseKey(line)
	if err != nil {
		t.Fatal(err)
	}
	return pgs.KeyInput{Normalized: pk.Normalized}
}

type backend struct {
	name string
	run  func(t *testing.T, dbPath string) sqlrun.Runner
}

var backends = []backend{
	{"embedded", func(t *testing.T, p string) sqlrun.Runner { return &sqlrun.Embedded{Path: p, BusyTimeoutMS: 5000} }},
	{"cli", func(t *testing.T, p string) sqlrun.Runner {
		bin := testutil.FakeSQLite3(t)
		return &sqlrun.CLI{Command: bin + " " + sqlrun.ShellQuote(p), Exec: sqlrun.LocalExec{}, BusyTimeoutMS: 5000}
	}},
}

func exec(t *testing.T, path, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, path, q string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func i64(v int64) *int64 { return &v }

func TestAccountLifecycle(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			// What `pgs init admin <key>` leaves behind.
			exec(t, path, "INSERT INTO app_users (name) VALUES ('admin')")
			exec(t, path, "INSERT INTO public_keys (user_id, name, public_key) VALUES (1, 'main', 'ssh-ed25519 ADMINKEY')")
			exec(t, path, "INSERT INTO feature_flags (user_id, name, expires_at) VALUES (1, 'plus', '2100-01-01'), (1, 'admin', '2100-01-01')")

			st := pgs.NewStore(b.run(t, path), nil)
			k1, k2, k3 := newKey(t, ""), newKey(t, ""), newKey(t, "")
			k1.Description = "alice"

			// create
			acc, err := st.Create(ctx, "alice", []pgs.KeyInput{k1, k2}, pgs.AccessInput{ExpiresAt: "2200-01-01", Data: pgs.FlagData{StorageMax: i64(5000)}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if acc.ID == 1 || len(acc.Keys) != 2 || len(acc.Flags) != 1 {
				t.Fatalf("unexpected account %+v", acc)
			}
			descs := map[string]string{}
			for _, k := range acc.Keys {
				descs[k.PublicKey] = k.Description
			}
			if descs[k1.Normalized] != "alice" || descs[k2.Normalized] != "main" {
				t.Fatalf("descriptions: %v", descs)
			}
			if fd := acc.Flags[0].Parse(); fd.StorageMax == nil || *fd.StorageMax != 5000 || fd.FileMax != nil {
				t.Fatalf("flag data: %+v", acc.Flags[0])
			}
			flagID := acc.Flags[0].ID
			noAccess := pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}

			// admin's rows untouched, flags not attached to admin (pgs init bug avoided)
			if n := count(t, path, "SELECT count(*) FROM feature_flags WHERE user_id = 1"); n != 2 {
				t.Fatalf("admin flags: %d", n)
			}

			// duplicate name / admin name / foreign key
			if _, err := st.Create(ctx, "alice", []pgs.KeyInput{k3}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil); !errors.Is(err, pgs.ErrNameTaken) {
				t.Fatalf("want ErrNameTaken, got %v", err)
			}
			if _, err := st.Create(ctx, "admin", []pgs.KeyInput{k3}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil); !errors.Is(err, pgs.ErrProtected) {
				t.Fatalf("want ErrProtected, got %v", err)
			}
			var kc *pgs.KeyConflictError
			if _, err := st.Create(ctx, "bob", []pgs.KeyInput{k1}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil); !errors.As(err, &kc) || kc.Owner != "alice" {
				t.Fatalf("want KeyConflictError(alice), got %v", err)
			}
			if _, err := st.GetByName(ctx, "admin"); !errors.Is(err, pgs.ErrProtected) {
				t.Fatalf("GetByName(admin): %v", err)
			}
			if _, err := st.GetByID(ctx, 1); !errors.Is(err, pgs.ErrProtected) {
				t.Fatalf("GetByID(1): %v", err)
			}

			// update: drop k2, add k3, rename key description, change quota, rename account
			k1.Description = "alice laptop"
			acc, err = st.Update(ctx, acc.ID, "alice2", []pgs.KeyInput{k1, k3}, pgs.AccessInput{ExpiresAt: "2201-01-01", Data: pgs.FlagData{FileMax: i64(77)}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if acc.Name != "alice2" || len(acc.Keys) != 2 {
				t.Fatalf("after update: %+v", acc)
			}
			descs = map[string]string{}
			for _, k := range acc.Keys {
				descs[k.PublicKey] = k.Description
			}
			if descs[k1.Normalized] != "alice laptop" || descs[k3.Normalized] != "main" || descs[k2.Normalized] != "" {
				t.Fatalf("descriptions after update: %v", descs)
			}
			f := acc.Flags[0]
			if f.ID != flagID || f.ExpiresAt != "2201-01-01" {
				t.Fatalf("flag after update: %+v", f)
			}
			if fd := f.Parse(); fd.StorageMax != nil || fd.FileMax == nil || *fd.FileMax != 77 {
				t.Fatalf("flag data after update: %+v", f)
			}

			// resetting access to the defaults keeps the flag (the account must keep access) and clears its extras
			acc, err = st.Update(ctx, acc.ID, "alice2", []pgs.KeyInput{k1, k3}, noAccess, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(acc.Flags) != 1 || acc.Flags[0].ID != flagID || acc.Flags[0].ExpiresAt != pgs.DefaultExpiresAt {
				t.Fatalf("flag after reset: %+v", acc.Flags)
			}
			if fd := acc.Flags[0].Parse(); fd.StorageMax != nil || fd.FileMax != nil || fd.SpecialFileMax != nil {
				t.Fatalf("extras not cleared: %+v", acc.Flags[0])
			}
			if n := count(t, path, "SELECT count(*) FROM feature_flags"); n != 3 {
				t.Fatalf("total flags: %d", n)
			}

			// a flag deleted behind our back is recreated by the next update
			exec(t, path, "DELETE FROM feature_flags WHERE id = ?", flagID)
			acc, err = st.Update(ctx, acc.ID, "alice2", []pgs.KeyInput{k1, k3}, noAccess, nil)
			if err != nil {
				t.Fatal(err)
			}
			if acc.ManagedFlag() == nil {
				t.Fatal("pgs flag was not recreated")
			}

			// delete: guarded by projects
			exec(t, path, "INSERT INTO projects (user_id, name) VALUES (?, 'site')", acc.ID)
			exec(t, path, "INSERT INTO form_entries (user_id, name, data) VALUES (?, 'f', '{}')", acc.ID)
			if err := st.Delete(ctx, acc.ID, false); !errors.Is(err, pgs.ErrHasProjects) {
				t.Fatalf("want ErrHasProjects, got %v", err)
			}
			if err := st.Delete(ctx, acc.ID, true); err != nil {
				t.Fatal(err)
			}
			for _, q := range []string{"app_users", "public_keys", "projects", "form_entries", "feature_flags"} {
				want := 0
				switch q {
				case "app_users", "public_keys":
					want = 1
				case "feature_flags":
					want = 2
				}
				if n := count(t, path, "SELECT count(*) FROM "+q); n != want {
					t.Fatalf("%s rows after delete: %d, want %d", q, n, want)
				}
			}
			if err := st.Delete(ctx, acc.ID, true); err != nil {
				t.Fatalf("second delete should be a no-op: %v", err)
			}
		})
	}
}

func TestProtectedNamesAndGuards(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			exec(t, path, "INSERT INTO app_users (name) VALUES ('ops')")
			st := pgs.NewStore(b.run(t, path), []string{"ops"})
			if _, err := st.GetByName(ctx, "ops"); !errors.Is(err, pgs.ErrProtected) {
				t.Fatalf("want ErrProtected, got %v", err)
			}
			if err := st.Delete(ctx, 1, true); !errors.Is(err, pgs.ErrProtected) {
				t.Fatalf("want ErrProtected, got %v", err)
			}
			if n := count(t, path, "SELECT count(*) FROM app_users"); n != 1 {
				t.Fatalf("protected user was deleted")
			}
		})
	}
}

func TestSchemaCheckRejectsForeignDB(t *testing.T) {
	path := testutil.NewPgsDB(t, "testdata/schema.sql")
	exec(t, path, "DROP TABLE projects")
	st := pgs.NewStore(&sqlrun.Embedded{Path: path, BusyTimeoutMS: 100}, nil)
	err := st.CheckSchema(context.Background())
	if err == nil || !strings.Contains(err.Error(), "projects") {
		t.Fatalf("want missing projects error, got %v", err)
	}
}

func TestQuotingInDescriptions(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			st := pgs.NewStore(b.run(t, path), []string{"nobody"})
			k := newKey(t, "")
			k.Description = "o'brien\nline2 ? \"q\" ; DROP TABLE app_users; --"
			acc, err := st.Create(ctx, "quote", []pgs.KeyInput{k}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if acc.Keys[0].Description != k.Description {
				t.Fatalf("description mangled: %q", acc.Keys[0].Description)
			}
		})
	}
}

func TestLongMultilineDescription(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			st := pgs.NewStore(b.run(t, path), []string{"nobody"})
			k := newKey(t, "")
			k.Description = strings.Repeat("é'\n", 50000)
			acc, err := st.Create(context.Background(), "long", []pgs.KeyInput{k}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if acc.Keys[0].Description != k.Description {
				t.Fatal("description mangled")
			}
		})
	}
}

func TestFailsClosedWithoutAdmin(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			st := pgs.NewStore(b.run(t, path), nil)
			k := newKey(t, "")
			if _, err := st.Create(context.Background(), "first", []pgs.KeyInput{k}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil); !errors.Is(err, pgs.ErrNoAdmin) {
				t.Fatalf("want ErrNoAdmin, got %v", err)
			}
			if n := count(t, path, "SELECT count(*) FROM app_users"); n != 0 {
				t.Fatal("account created without an admin present")
			}
		})
	}
}

func TestMultiLineKeyRejected(t *testing.T) {
	a, b := newKey(t, ""), newKey(t, "")
	if _, err := pgs.ParseKey("ssh-ed25519 x\n" + a.Normalized + "\n" + b.Normalized); err == nil {
		t.Fatal("want error for multi-line key")
	}
	if _, err := pgs.ParseKey(a.Normalized + "\n"); err != nil {
		t.Fatalf("trailing newline must be fine: %v", err)
	}
}

// hookRunner runs before hook before every write batch, to simulate a concurrent change.
type hookRunner struct {
	sqlrun.Runner
	before func()
}

func (h hookRunner) Run(ctx context.Context, m sqlrun.Mode, st []sqlrun.Statement) ([]string, error) {
	if m == sqlrun.ModeWrite && h.before != nil {
		h.before()
	}
	return h.Runner.Run(ctx, m, st)
}

func TestDeleteWithoutForceNeverDeletesProjects(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			exec(t, path, "INSERT INTO app_users (name) VALUES ('admin')")
			exec(t, path, "INSERT INTO feature_flags (user_id, name, expires_at) VALUES (1, 'admin', '2100-01-01')")
			hook := hookRunner{Runner: b.run(t, path)}
			st := pgs.NewStore(hook, nil)
			acc, err := st.Create(ctx, "carol", []pgs.KeyInput{newKey(t, "")}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil)
			if err != nil {
				t.Fatal(err)
			}
			// A project appears after Delete checked for projects but before its write batch runs.
			hook.before = func() { exec(t, path, "INSERT INTO projects (user_id, name) VALUES (?, 'p')", acc.ID) }
			st = pgs.NewStore(hook, nil)
			if err := st.Delete(ctx, acc.ID, false); !errors.Is(err, pgs.ErrHasProjects) {
				t.Fatalf("want ErrHasProjects, got %v", err)
			}
			if n := count(t, path, "SELECT count(*) FROM projects"); n != 1 {
				t.Fatalf("project was deleted: %d", n)
			}
			if n := count(t, path, "SELECT count(*) FROM app_users WHERE name = 'carol'"); n != 1 {
				t.Fatal("account was deleted")
			}
		})
	}
}

// pgs < v3.24.0 has no form_entries table.
func TestWorksWithoutFormEntriesTable(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			exec(t, path, "DROP TABLE form_entries")
			st := pgs.NewStore(b.run(t, path), []string{"nobody"})
			acc, err := st.Create(ctx, "old", []pgs.KeyInput{newKey(t, "")}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.Delete(ctx, acc.ID, true); err != nil {
				t.Fatal(err)
			}
			if n := count(t, path, "SELECT count(*) FROM app_users"); n != 0 {
				t.Fatalf("account not deleted")
			}
		})
	}
}

func TestAccountRequiresKey(t *testing.T) {
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			path := testutil.NewPgsDB(t, "testdata/schema.sql")
			exec(t, path, "INSERT INTO app_users (name) VALUES ('ops')")
			st := pgs.NewStore(b.run(t, path), []string{"ops"})
			acc := pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}
			if _, err := st.Create(ctx, "bob", nil, acc, nil); !errors.Is(err, pgs.ErrNoKeys) {
				t.Fatalf("create: want ErrNoKeys, got %v", err)
			}
			created, err := st.Create(ctx, "bob", []pgs.KeyInput{newKey(t, "")}, acc, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Update(ctx, created.ID, "bob", nil, acc, nil); !errors.Is(err, pgs.ErrNoKeys) {
				t.Fatalf("update: want ErrNoKeys, got %v", err)
			}
			if n := count(t, path, "SELECT count(*) FROM public_keys WHERE user_id = ?", created.ID); n != 1 {
				t.Fatalf("keys changed: %d", n)
			}
		})
	}
}
