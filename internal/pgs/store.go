// Package pgs manages pgs accounts (app_users, public_keys, feature_flags)
// directly in pgs's SQLite database.
package pgs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

const (
	// FlagName is the feature flag that grants a user access to pgs (uploads). Every managed account has one.
	FlagName = "pgs"
	// DefaultExpiresAt is the expiry written when none is configured.
	DefaultExpiresAt = "2200-01-01"
)

// form_entries only exists in pgs >= v3.24.0, so it is optional.
var requiredTables = []string{"app_users", "public_keys", "feature_flags", "projects"}

var (
	ErrProtected   = errors.New("account is protected (admin) and never managed by this provider")
	ErrNameTaken   = errors.New("an account with this name already exists")
	ErrNotFound    = errors.New("account not found")
	ErrNoKeys      = errors.New("an account must have at least one public key")
	ErrHasProjects = errors.New("account still has projects")
	ErrNoAdmin     = errors.New("no account holds the `admin` feature flag, so the provider cannot tell which account is the admin; run `pgs init <admin-name> <key>` first, or list the admin account in the provider's protected_accounts")
)

// KeyConflictError reports a key that is already registered for another account.
type KeyConflictError struct {
	Key, Owner string
	Protected  bool
}

func (e *KeyConflictError) Error() string {
	if e.Protected {
		return fmt.Sprintf("public key %q is already registered for the protected admin account %q, which this provider never touches", short(e.Key), e.Owner)
	}
	return fmt.Sprintf("public key %q is already registered for account %q", short(e.Key), e.Owner)
}

func short(k string) string {
	if len(k) > 40 {
		return k[:40] + "…"
	}
	return k
}

type Key struct {
	ID          int64  `json:"id"`
	PublicKey   string `json:"public_key"`
	Description string `json:"description"`
}

type Flag struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
	Data      string `json:"data"`
}

// FlagData are the quota fields pgs reads from feature_flags.data; nil = unset (pgs default).
type FlagData struct {
	StorageMax     *int64 `json:"storage_max,omitempty"`
	FileMax        *int64 `json:"file_max,omitempty"`
	SpecialFileMax *int64 `json:"special_file_max,omitempty"`
}

// Parse extracts the quota fields from the flag's JSON data; invalid JSON yields zero values.
func (f Flag) Parse() FlagData {
	var d FlagData
	_ = json.Unmarshal([]byte(f.Data), &d)
	// pgs treats 0 as "default" too, so normalise it to unset.
	for _, p := range []**int64{&d.StorageMax, &d.FileMax, &d.SpecialFileMax} {
		if *p != nil && **p == 0 {
			*p = nil
		}
	}
	return d
}

type Account struct {
	ID        int64
	Name      string
	CreatedAt string
	Projects  int64
	Keys      []Key
	Flags     []Flag
	Protected bool
}

// ManagedFlag returns the account's pgs flag: the newest one (by expiry, then id) named FlagName, nil if none.
func (a *Account) ManagedFlag() *Flag {
	var best *Flag
	for i := range a.Flags {
		f := &a.Flags[i]
		if f.Name == FlagName && (best == nil || f.ExpiresAt >= best.ExpiresAt) {
			best = f
		}
	}
	return best
}

// KeyInput is a desired key. Description "" means "use the default description".
type KeyInput struct {
	Normalized  string
	Description string
}

// AccessInput is the desired content of the pgs flag. The flag always exists; this is its metadata.
type AccessInput struct {
	ExpiresAt string
	Data      FlagData
}

type Store struct {
	r         sqlrun.Runner
	protected []string

	mu     sync.Mutex
	schema bool
	forms  bool // the form_entries table exists

	claimMu sync.Mutex
	claims  map[string]string // normalized key -> account name that claimed it in this run
}

func NewStore(r sqlrun.Runner, protectedNames []string) *Store {
	return &Store{r: r, protected: protectedNames}
}

func (s *Store) query(ctx context.Context, sql string, args ...any) (string, error) {
	out, err := s.r.Run(ctx, sqlrun.ModeRead, []sqlrun.Statement{{SQL: sql, Args: args, Query: true}})
	if err != nil {
		return "", err
	}
	return out[0], nil
}

// CheckSchema verifies the database looks like a pgs database. The result is cached on success.
func (s *Store) CheckSchema(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.schema {
		return nil
	}
	out, err := s.query(ctx, `SELECT json_object('user_version', (SELECT user_version FROM pragma_user_version), 'tables', json((SELECT coalesce(json_group_array(name), '[]') FROM sqlite_master WHERE type = 'table')))`)
	if err != nil {
		return err
	}
	var res struct {
		UserVersion int      `json:"user_version"`
		Tables      []string `json:"tables"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return fmt.Errorf("decode schema check %q: %w", out, err)
	}
	have := map[string]bool{}
	for _, t := range res.Tables {
		have[t] = true
	}
	var missing []string
	for _, t := range requiredTables {
		if !have[t] {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the database does not look like a pgs database (missing tables: %s); start pgs once so it creates its schema", strings.Join(missing, ", "))
	}
	// Fail closed: the admin is recognised by its `admin` flag. If none exists (pgs init has not
	// run yet) we could not tell the admin apart, so refuse to work unless names are protected explicitly.
	if len(s.protected) == 0 {
		out, err := s.query(ctx, `SELECT json_object('admins', (SELECT count(*) FROM feature_flags WHERE name = 'admin'))`)
		if err != nil {
			return err
		}
		var a struct {
			Admins int `json:"admins"`
		}
		if err := json.Unmarshal([]byte(out), &a); err != nil {
			return fmt.Errorf("decode admin check %q: %w", out, err)
		}
		if a.Admins == 0 {
			return ErrNoAdmin
		}
	}
	s.schema = true
	s.forms = have["form_entries"]
	return nil
}

const accountSelect = `SELECT coalesce(json_group_array(json_object(
 'id', u.id, 'name', u.name, 'created_at', u.created_at,
 'is_admin', EXISTS(SELECT 1 FROM feature_flags a WHERE a.user_id = u.id AND a.name = 'admin'),
 'projects', (SELECT count(*) FROM projects p WHERE p.user_id = u.id),
 'keys', json((SELECT coalesce(json_group_array(json_object('id', k.id, 'public_key', k.public_key, 'description', k.name)), '[]') FROM public_keys k WHERE k.user_id = u.id)),
 'flags', json((SELECT coalesce(json_group_array(json_object('id', f.id, 'name', f.name, 'expires_at', f.expires_at, 'data', CAST(f.data AS TEXT))), '[]') FROM feature_flags f WHERE f.user_id = u.id))
)), '[]') FROM app_users u WHERE `

func (s *Store) isProtectedName(name string) bool {
	for _, p := range s.protected {
		if p == name {
			return true
		}
	}
	return false
}

// get loads an account by "u.id = ?" / "u.name = ?". It returns (nil, nil) when absent.
// Protected accounts are returned with Protected=true so callers can decide.
func (s *Store) get(ctx context.Context, where string, arg any) (*Account, error) {
	if err := s.CheckSchema(ctx); err != nil {
		return nil, err
	}
	out, err := s.query(ctx, accountSelect+where, arg)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
		IsAdmin   int    `json:"is_admin"`
		Projects  int64  `json:"projects"`
		Keys      []Key  `json:"keys"`
		Flags     []Flag `json:"flags"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, fmt.Errorf("decode account %q: %w", out, err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	sort.Slice(r.Keys, func(i, j int) bool { return r.Keys[i].ID < r.Keys[j].ID })
	sort.Slice(r.Flags, func(i, j int) bool { return r.Flags[i].ID < r.Flags[j].ID })
	return &Account{
		ID: r.ID, Name: r.Name, CreatedAt: r.CreatedAt, Projects: r.Projects, Keys: r.Keys, Flags: r.Flags,
		Protected: r.IsAdmin != 0 || s.isProtectedName(r.Name),
	}, nil
}

// GetByID returns (nil, nil) if the account does not exist and ErrProtected for protected accounts.
func (s *Store) GetByID(ctx context.Context, id int64) (*Account, error) {
	return s.checkProtected(s.get(ctx, "u.id = ?", id))
}

// GetByName behaves like GetByID, looking the account up by name.
func (s *Store) GetByName(ctx context.Context, name string) (*Account, error) {
	return s.checkProtected(s.get(ctx, "u.name = ?", name))
}

func (s *Store) checkProtected(a *Account, err error) (*Account, error) {
	if err != nil {
		return nil, err
	}
	if a != nil && a.Protected {
		return nil, fmt.Errorf("%q: %w", a.Name, ErrProtected)
	}
	return a, nil
}

// guard returns an SQL condition excluding protected users for the given user-id column.
func (s *Store) guard(col string) (string, []any) {
	cond := col + " NOT IN (SELECT user_id FROM feature_flags WHERE name = 'admin')"
	var args []any
	if len(s.protected) > 0 {
		cond += " AND " + col + " NOT IN (SELECT id FROM app_users WHERE name IN (" + strings.TrimSuffix(strings.Repeat("?,", len(s.protected)), ",") + "))"
		for _, p := range s.protected {
			args = append(args, p)
		}
	}
	return cond, args
}

// guarded appends the protection condition for userCol to a statement that already has a WHERE
// clause; the guard args follow the statement args.
func (s *Store) guarded(sql, userCol string, args ...any) sqlrun.Statement {
	cond, gargs := s.guard(userCol)
	return sqlrun.Statement{SQL: sql + " AND " + cond, Args: append(args, gargs...)}
}

// checkKeyConflicts fails if any key is registered for an account other than ownerID (0 = none).
func (s *Store) checkKeyConflicts(ctx context.Context, ownerID int64, keys []KeyInput) error {
	if len(keys) == 0 {
		return nil
	}
	args := make([]any, 0, len(keys)+1)
	args = append(args, ownerID)
	for _, k := range keys {
		args = append(args, k.Normalized)
	}
	out, err := s.query(ctx, `SELECT coalesce(json_group_array(json_object('key', k.public_key, 'owner', u.name, 'admin', EXISTS(SELECT 1 FROM feature_flags a WHERE a.user_id = u.id AND a.name = 'admin'))), '[]') FROM public_keys k JOIN app_users u ON u.id = k.user_id WHERE k.user_id <> ? AND k.public_key IN (`+strings.TrimSuffix(strings.Repeat("?,", len(keys)), ",")+`)`, args...)
	if err != nil {
		return err
	}
	var rows []struct {
		Key   string `json:"key"`
		Owner string `json:"owner"`
		Admin int    `json:"admin"`
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		return fmt.Errorf("decode key conflicts %q: %w", out, err)
	}
	if len(rows) > 0 {
		return &KeyConflictError{Key: rows[0].Key, Owner: rows[0].Owner, Protected: rows[0].Admin != 0 || s.isProtectedName(rows[0].Owner)}
	}
	return nil
}

func desc(k KeyInput, comment string) string {
	if k.Description != "" {
		return k.Description
	}
	return DefaultDescription(comment)
}

func flagDataJSON(d FlagData) string {
	b, _ := json.Marshal(d)
	return string(b)
}

// flagPatchJSON builds a JSON merge patch: unset fields are null, which removes them.
func flagPatchJSON(d FlagData) string {
	p := map[string]*int64{"storage_max": d.StorageMax, "file_max": d.FileMax, "special_file_max": d.SpecialFileMax}
	b, _ := json.Marshal(p)
	return string(b)
}

// Create inserts a new account with its keys and optional feature flag, atomically.
func (s *Store) Create(ctx context.Context, name string, keys []KeyInput, access AccessInput, comments map[string]string) (*Account, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%q: %w", name, ErrNoKeys)
	}
	if err := s.CheckSchema(ctx); err != nil {
		return nil, err
	}
	existing, err := s.get(ctx, "u.name = ?", name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.Protected {
			return nil, fmt.Errorf("%q: %w", name, ErrProtected)
		}
		return nil, fmt.Errorf("%q: %w (import it with `tofu import` to manage it)", name, ErrNameTaken)
	}
	if s.isProtectedName(name) {
		return nil, fmt.Errorf("%q: %w", name, ErrProtected)
	}
	if err := s.checkKeyConflicts(ctx, 0, keys); err != nil {
		return nil, err
	}
	uid := "(SELECT id FROM app_users WHERE name = ?)"
	stmts := []sqlrun.Statement{{SQL: "INSERT INTO app_users (name) VALUES (?)", Args: []any{name}}}
	for _, k := range keys {
		stmts = append(stmts, sqlrun.Statement{
			SQL:  "INSERT INTO public_keys (user_id, name, public_key) VALUES (" + uid + ", ?, ?)",
			Args: []any{name, desc(k, comments[k.Normalized]), k.Normalized},
		})
	}
	stmts = append(stmts, sqlrun.Statement{
		SQL:  "INSERT INTO feature_flags (user_id, name, expires_at, data) VALUES (" + uid + ", ?, ?, ?)",
		Args: []any{name, FlagName, access.ExpiresAt, flagDataJSON(access.Data)},
	})
	if _, err := s.r.Run(ctx, sqlrun.ModeWrite, stmts); err != nil {
		return nil, wrapConstraint(err)
	}
	acc, err := s.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, fmt.Errorf("account %q vanished right after creation", name)
	}
	return acc, nil
}

func wrapConstraint(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w (a concurrent change or a duplicate key/name?)", err)
	}
	return err
}

// Update reconciles name, keys and the pgs flag of account id; the flag is created if missing and
// never deleted. comments maps normalized key -> authorized_keys comment.
func (s *Store) Update(ctx context.Context, id int64, name string, keys []KeyInput, access AccessInput, comments map[string]string) (*Account, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("account id %d: %w", id, ErrNoKeys)
	}
	cur, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, fmt.Errorf("account id %d: %w", id, ErrNotFound)
	}
	var stmts []sqlrun.Statement
	if name != cur.Name {
		if s.isProtectedName(name) {
			return nil, fmt.Errorf("%q: %w", name, ErrProtected)
		}
		other, err := s.get(ctx, "u.name = ?", name)
		if err != nil {
			return nil, err
		}
		if other != nil {
			return nil, fmt.Errorf("cannot rename to %q: %w", name, ErrNameTaken)
		}
		stmts = append(stmts, s.guarded("UPDATE app_users SET name = ? WHERE id = ?", "id", name, id))
	}

	have := map[string]Key{}
	for _, k := range cur.Keys {
		have[k.PublicKey] = k
	}
	want := map[string]KeyInput{}
	var added []KeyInput
	for _, k := range keys {
		want[k.Normalized] = k
		if _, ok := have[k.Normalized]; !ok {
			added = append(added, k)
		}
	}
	if err := s.checkKeyConflicts(ctx, id, added); err != nil {
		return nil, err
	}
	for _, k := range cur.Keys { // deletes first, then updates, then inserts
		if _, ok := want[k.PublicKey]; !ok {
			stmts = append(stmts, s.guarded("DELETE FROM public_keys WHERE user_id = ? AND public_key = ?", "user_id", id, k.PublicKey))
		}
	}
	for _, k := range keys {
		if h, ok := have[k.Normalized]; ok {
			if d := desc(k, comments[k.Normalized]); d != h.Description {
				stmts = append(stmts, s.guarded("UPDATE public_keys SET name = ? WHERE user_id = ? AND public_key = ?", "user_id", d, id, k.Normalized))
			}
		}
	}
	for _, k := range added {
		stmts = append(stmts, s.guarded("INSERT INTO public_keys (user_id, name, public_key) SELECT id, ?, ? FROM app_users WHERE id = ?", "id", desc(k, comments[k.Normalized]), k.Normalized, id))
	}

	if curFlag := cur.ManagedFlag(); curFlag != nil {
		stmts = append(stmts, s.guarded("UPDATE feature_flags SET expires_at = ?, data = json_patch(CASE WHEN json_valid(data) THEN CAST(data AS TEXT) ELSE '{}' END, ?) WHERE id = ? AND name = ? AND user_id = ?", "user_id",
			access.ExpiresAt, flagPatchJSON(access.Data), curFlag.ID, FlagName, id))
	} else {
		stmts = append(stmts, s.guarded("INSERT INTO feature_flags (user_id, name, expires_at, data) SELECT id, ?, ?, ? FROM app_users WHERE id = ?", "id", FlagName, access.ExpiresAt, flagDataJSON(access.Data), id))
	}

	if len(stmts) > 0 {
		if _, err := s.r.Run(ctx, sqlrun.ModeWrite, stmts); err != nil {
			return nil, wrapConstraint(err)
		}
	}
	acc, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, fmt.Errorf("account id %d vanished during update", id)
	}
	return acc, nil
}

// Delete removes the account and everything attached to it. It is a no-op if the account is gone.
func (s *Store) Delete(ctx context.Context, id int64, force bool) error {
	cur, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return nil
	}
	if cur.Projects > 0 && !force {
		return fmt.Errorf("%q has %d project(s): %w; set force_destroy = true to delete them too (site files in object storage are not removed)", cur.Name, cur.Projects, ErrHasProjects)
	}
	// Without force, every delete also requires "no projects" inside the transaction, so a project
	// created after the check above is never deleted silently; we verify the outcome afterwards.
	noProj := ""
	if !force {
		noProj = " AND NOT EXISTS (SELECT 1 FROM projects WHERE user_id = ?)"
	}
	del := func(sql, col string) sqlrun.Statement {
		st := s.guarded(sql, col, id)
		if !force {
			st.SQL += noProj
			st.Args = append(st.Args, id)
		}
		return st
	}
	var stmts []sqlrun.Statement
	if s.forms {
		stmts = append(stmts, del("DELETE FROM form_entries WHERE user_id = ?", "user_id"))
	}
	if force {
		stmts = append(stmts, del("DELETE FROM projects WHERE user_id = ?", "user_id"))
	}
	stmts = append(stmts,
		del("DELETE FROM feature_flags WHERE user_id = ?", "user_id"),
		del("DELETE FROM public_keys WHERE user_id = ?", "user_id"),
		del("DELETE FROM app_users WHERE id = ?", "id"),
	)
	if _, err = s.r.Run(ctx, sqlrun.ModeWrite, stmts); err != nil {
		return err
	}
	// The statements are guarded, so a guard that matched nothing commits as a silent no-op:
	// always confirm the account is really gone before reporting success.
	left, err := s.get(ctx, "u.id = ?", id)
	if err != nil {
		return err
	}
	if left != nil {
		if left.Protected {
			return fmt.Errorf("%q: %w (it became protected during the apply); nothing was deleted", cur.Name, ErrProtected)
		}
		return fmt.Errorf("%q: %w (a project was created concurrently); nothing was deleted", cur.Name, ErrHasProjects)
	}
	return nil
}
