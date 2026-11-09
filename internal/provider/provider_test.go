package provider_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"golang.org/x/crypto/ssh"

	"github.com/innoq/terraform-provider-pgs/internal/provider"
	"github.com/innoq/terraform-provider-pgs/internal/testutil"
)

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"pgs": providerserver.NewProtocol6WithError(provider.New("test")()),
}

func genKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func sqlExec(t *testing.T, path, q string, args ...any) {
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

func sqlCount(t *testing.T, path, q string, args ...any) int {
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

func newDB(t *testing.T) string {
	t.Helper()
	path := testutil.NewPgsDB(t, "../pgs/testdata/schema.sql")
	// What `pgs init admin <key>` leaves behind.
	sqlExec(t, path, "INSERT INTO app_users (name) VALUES ('admin')")
	sqlExec(t, path, "INSERT INTO public_keys (user_id, name, public_key) VALUES (1, 'main', 'ssh-ed25519 ADMINKEY')")
	sqlExec(t, path, "INSERT INTO feature_flags (user_id, name, expires_at) VALUES (1, 'plus', '2100-01-01'), (1, 'admin', '2100-01-01')")
	return path
}

const requiredProviders = `terraform {
  required_providers {
    pgs = { source = "registry.opentofu.org/local/pgs" }
  }
}
`

func providerBlock(dbPath, kind string, t *testing.T) string {
	switch kind {
	case "cli":
		return requiredProviders + fmt.Sprintf(`provider "pgs" { sqlite_command = "%s %s" }`, testutil.FakeSQLite3(t), dbPath)
	default:
		return requiredProviders + fmt.Sprintf(`provider "pgs" { database_path = %q }`, dbPath)
	}
}

func TestAccAccount(t *testing.T) {
	for _, kind := range []string{"embedded", "cli"} {
		t.Run(kind, func(t *testing.T) {
			db := newDB(t)
			pb := providerBlock(db, kind, t)
			a, b, c := genKey(t), genKey(t), genKey(t)

			cfg := func(body string) string { return pb + "\n" + body }
			base := cfg(fmt.Sprintf(`
resource "pgs_account" "alice" {
  name = "alice"
  public_keys = [
    { key = %q, description = "alice" },
    { key = %q },
  ]
  access = { storage_max = 5000000000 }
}`, a, b))

			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: factories,
				Steps: []resource.TestStep{
					{
						Config: base,
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("pgs_account.alice", "name", "alice"),
							resource.TestCheckResourceAttr("pgs_account.alice", "public_keys.#", "2"),
							resource.TestCheckResourceAttr("pgs_account.alice", "access.expires_at", "2200-01-01"),
							resource.TestCheckResourceAttr("pgs_account.alice", "access.storage_max", "5000000000"),
							resource.TestCheckResourceAttrSet("pgs_account.alice", "flag_id"),
						),
					},
					{ // no drift right after apply
						Config:   base,
						PlanOnly: true,
					},
					{ // drift: a key added behind Terraform's back is reported and removed again
						PreConfig: func() {
							sqlExec(t, db, "INSERT INTO public_keys (user_id, name, public_key) VALUES (2, 'rogue', 'ssh-ed25519 ROGUE')")
						},
						Config:             base,
						PlanOnly:           true,
						ExpectNonEmptyPlan: true,
					},
					{ // drift: quota changed externally
						PreConfig: func() {
							sqlExec(t, db, "DELETE FROM public_keys WHERE name = 'rogue'")
							sqlExec(t, db, `UPDATE feature_flags SET data = '{"storage_max": 1}' WHERE user_id = 2`)
						},
						Config:             base,
						PlanOnly:           true,
						ExpectNonEmptyPlan: true,
					},
					{ // apply repairs the drift
						Config: base,
						Check:  resource.TestCheckResourceAttr("pgs_account.alice", "access.storage_max", "5000000000"),
					},
					{ // update: swap key b for c, change description and quota
						Config: cfg(fmt.Sprintf(`
resource "pgs_account" "alice" {
  name = "alice"
  public_keys = [
    { key = %q, description = "alice laptop" },
    { key = %q, description = "bob" },
  ]
  access = { storage_max = 1000, file_max = 500, expires_at = "2300-01-01" }
}`, a, c)),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttr("pgs_account.alice", "access.storage_max", "1000"),
							resource.TestCheckResourceAttr("pgs_account.alice", "access.file_max", "500"),
							resource.TestCheckResourceAttr("pgs_account.alice", "access.expires_at", "2300-01-01"),
							resource.TestCheckTypeSetElemNestedAttrs("pgs_account.alice", "public_keys.*", map[string]string{"key": c, "description": "bob"}),
						),
					},
					{ // import by name
						ResourceName:                         "pgs_account.alice",
						ImportState:                          true,
						ImportStateId:                        "alice",
						ImportStateVerify:                    true,
						ImportStateVerifyIdentifierAttribute: "name",
					},
					{ // remove the access block: the pgs flag stays (the account keeps access), its extras reset
						Config: cfg(fmt.Sprintf(`
resource "pgs_account" "alice" {
  name = "alice"
  public_keys = [{ key = %q }]
}`, a)),
						Check: resource.ComposeTestCheckFunc(
							resource.TestCheckResourceAttrSet("pgs_account.alice", "flag_id"),
							resource.TestCheckNoResourceAttr("pgs_account.alice", "access.storage_max"),
							func(*terraform.State) error {
								if n := sqlCount(t, db, "SELECT count(*) FROM feature_flags WHERE name = 'pgs' AND user_id = 2 AND expires_at = '2200-01-01' AND data = '{}'"); n != 1 {
									return fmt.Errorf("want one default pgs flag, got %d", n)
								}
								return nil
							},
						),
					},
					{ // data source
						Config: cfg(fmt.Sprintf(`
resource "pgs_account" "alice" {
  name = "alice"
  public_keys = [{ key = %q }]
}
data "pgs_account" "alice" {
  name = pgs_account.alice.name
}`, a)),
						Check: resource.TestCheckResourceAttrPair("data.pgs_account.alice", "id", "pgs_account.alice", "id"),
					},
					{ // two keys right before the destroy that ends the test
						Config: cfg(fmt.Sprintf(`
resource "pgs_account" "alice" {
  name = "alice"
  public_keys = [{ key = %q }, { key = %q, description = "bob" }]
}`, a, c)),
						Check: func(*terraform.State) error {
							if n := sqlCount(t, db, "SELECT count(*) FROM public_keys WHERE user_id = 2"); n != 2 {
								return fmt.Errorf("want 2 keys for alice before destroy, got %d", n)
							}
							return nil
						},
					},
				},
				// Destroying the account removes all of its keys and its flag, and nothing of the admin's.
				CheckDestroy: func(*terraform.State) error {
					for q, want := range map[string]int{
						"SELECT count(*) FROM app_users WHERE name = 'alice'":  0,
						"SELECT count(*) FROM public_keys WHERE user_id = 2":   0,
						"SELECT count(*) FROM public_keys":                     1, // only the admin's key is left
						"SELECT count(*) FROM feature_flags WHERE user_id = 2": 0,
						"SELECT count(*) FROM feature_flags WHERE user_id = 1": 2,
					} {
						if n := sqlCount(t, db, q); n != want {
							return fmt.Errorf("after destroy: %q = %d, want %d", q, n, want)
						}
					}
					return nil
				},
			})
		})
	}
}

func TestAccAdminIsNeverManaged(t *testing.T) {
	db := newDB(t)
	pb := providerBlock(db, "embedded", t)
	k := genKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      pb + fmt.Sprintf("\nresource \"pgs_account\" \"admin\" {\n name = \"admin\"\n public_keys = [{ key = %q }]\n}", k),
				ExpectError: regexp.MustCompile(`(?s)protected`),
			},
			{
				Config:        pb + "\nresource \"pgs_account\" \"admin\" {\n name = \"admin\"\n public_keys = [{ key = \"" + k + "\" }]\n}",
				ResourceName:  "pgs_account.admin",
				ImportState:   true,
				ImportStateId: "admin",
				ExpectError:   regexp.MustCompile(`(?s)protected`),
			},
			{
				Config:      pb + "\nresource \"pgs_account\" \"x\" {\n name = \"x\"\n public_keys = [{ key = \"" + k + "\" }]\n}\ndata \"pgs_account\" \"a\" {\n name = \"admin\"\n}",
				ExpectError: regexp.MustCompile(`(?s)protected`),
			},
		},
	})
}

func TestAccDriftDeletedAccountIsRecreated(t *testing.T) {
	db := newDB(t)
	pb := providerBlock(db, "embedded", t)
	k := genKey(t)
	cfg := pb + fmt.Sprintf("\nresource \"pgs_account\" \"p\" {\n name = \"proj\"\n public_keys = [{ key = %q }]\n}", k)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig: func() {
					sqlExec(t, db, "PRAGMA foreign_keys = ON")
					sqlExec(t, db, "DELETE FROM public_keys WHERE user_id = 2")
					sqlExec(t, db, "DELETE FROM app_users WHERE id = 2")
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{Config: cfg, Check: resource.TestCheckResourceAttr("pgs_account.p", "public_keys.#", "1")},
		},
	})
}

func TestAccInputValidation(t *testing.T) {
	db := newDB(t)
	pb := providerBlock(db, "embedded", t)
	a, b := genKey(t), genKey(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{ // an account without any key is rejected at plan time
				Config:      pb + "\nresource \"pgs_account\" \"v\" {\n name = \"v\"\n public_keys = []\n}",
				ExpectError: regexp.MustCompile(`(?s)at\s+least\s+1`),
			},
			{ // empty description would never converge: rejected up front
				Config:      pb + fmt.Sprintf("\nresource \"pgs_account\" \"v\" {\n name = \"v\"\n public_keys = [{ key = %q, description = \"\" }]\n}", a),
				ExpectError: regexp.MustCompile(`(?s)at least 1`),
			},
			{ // several keys in one string must not silently drop all but the first
				Config:      pb + fmt.Sprintf("\nresource \"pgs_account\" \"v\" {\n name = \"v\"\n public_keys = [{ key = %q }]\n}", a+"\n"+b),
				ExpectError: regexp.MustCompile(`(?s)single\s+line`),
			},
		},
	})
}

func TestAccFailsClosedWithoutAdmin(t *testing.T) {
	db := testutil.NewPgsDB(t, "../pgs/testdata/schema.sql") // no admin, no protected_accounts
	pb := providerBlock(db, "embedded", t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{{
			Config:      pb + fmt.Sprintf("\nresource \"pgs_account\" \"x\" {\n name = \"x\"\n public_keys = [{ key = %q }]\n}", genKey(t)),
			ExpectError: regexp.MustCompile(`(?s)pgs\s+init`),
		}},
	})
}

func TestAccFlagAlwaysExists(t *testing.T) {
	db := newDB(t)
	pb := providerBlock(db, "embedded", t)
	k := genKey(t)
	cfg := pb + fmt.Sprintf("\nresource \"pgs_account\" \"p\" {\n name = \"proj\"\n public_keys = [{ key = %q }]\n}", k)
	flags := func() int {
		return sqlCount(t, db, "SELECT count(*) FROM feature_flags WHERE name = 'pgs' AND user_id = 2")
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{ // no access block: the account still gets its pgs flag
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("pgs_account.p", "flag_id"),
					resource.TestCheckNoResourceAttr("pgs_account.p", "access.expires_at"),
					func(*terraform.State) error {
						if flags() != 1 {
							return fmt.Errorf("want 1 pgs flag, got %d", flags())
						}
						return nil
					},
				),
			},
			{Config: cfg, PlanOnly: true}, // converged: omitted access is not drift
			{ // the flag is deleted behind our back: the plan must show it
				PreConfig:          func() { sqlExec(t, db, "DELETE FROM feature_flags WHERE name = 'pgs' AND user_id = 2") },
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{ // and apply restores it
				Config: cfg,
				Check: func(*terraform.State) error {
					if flags() != 1 {
						return fmt.Errorf("pgs flag not restored, got %d", flags())
					}
					return nil
				},
			},
			{ // quotas edited externally are drift too, and are reset
				PreConfig: func() {
					sqlExec(t, db, `UPDATE feature_flags SET data = '{"storage_max": 7}' WHERE name = 'pgs' AND user_id = 2`)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: cfg,
				Check: func(*terraform.State) error {
					if n := sqlCount(t, db, "SELECT count(*) FROM feature_flags WHERE name = 'pgs' AND data = '{}'"); n != 1 {
						return fmt.Errorf("extras not reset (%d)", n)
					}
					return nil
				},
			},
		},
	})
}

func TestAccKeyUsedOnceAtPlanTime(t *testing.T) {
	db := newDB(t)
	pb := providerBlock(db, "embedded", t)
	shared, own := genKey(t), genKey(t)
	acct := func(name, key string) string {
		return fmt.Sprintf("\nresource \"pgs_account\" %q {\n name = %q\n public_keys = [{ key = %q }]\n}", name, name, key)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{ // two accounts of one configuration share a key: caught while planning
				Config:             pb + acct("one", shared) + acct("two", shared),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				ExpectError:        regexp.MustCompile(`(?s)more\s+than\s+one\s+account`),
			},
			{
				Config: pb + acct("one", shared),
			},
			{ // the key already belongs to "one" in the database: caught while planning, nothing applied
				Config:      pb + acct("one", shared) + acct("two", shared),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)already\s+in\s+use`),
			},
			{ // a key is not a conflict with its own account
				Config: pb + acct("one", shared) + acct("two", own),
			},
		},
	})
}
