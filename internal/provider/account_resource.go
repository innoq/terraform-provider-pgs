package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/innoq/terraform-provider-pgs/internal/pgs"
)

var (
	_ resource.Resource                   = (*accountResource)(nil)
	_ resource.ResourceWithConfigure      = (*accountResource)(nil)
	_ resource.ResourceWithImportState    = (*accountResource)(nil)
	_ resource.ResourceWithValidateConfig = (*accountResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*accountResource)(nil)
)

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9]+$`)
	expiresRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$`)
)

type accountResource struct{ store *pgs.Store }

func NewAccountResource() resource.Resource { return &accountResource{} }

type accountModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	CreatedAt    types.String `tfsdk:"created_at"`
	PublicKeys   types.Set    `tfsdk:"public_keys"`
	Access       types.Object `tfsdk:"access"`
	FlagID       types.String `tfsdk:"flag_id"`
	ForceDestroy types.Bool   `tfsdk:"force_destroy"`
}

func (r *accountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_account"
}

func (r *accountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A pgs account: a user name, its SSH public keys and (optionally) the feature flag that allows uploading. " +
			"The admin account (holder of the `admin` feature flag) can never be managed.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "The numeric id of the account in pgs's app_users table.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required: true,
				Description: "Account name. Lowercase letters and digits only: pgs serves sites at `<account>-<project>.<domain>` and splits on the first `-`. " +
					"Renaming changes the URLs of all the account's sites.",
				Validators: []validator.String{stringvalidator.RegexMatches(nameRE, "must match ^[a-z0-9]+$")},
			},
			"created_at": schema.StringAttribute{
				Computed: true, Description: "Creation timestamp as stored by pgs.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"public_keys": schema.SetNestedAttribute{
				Required:    true,
				Description: "SSH public keys that log in as this account. At least one is required. A key can belong to one account only.",
				Validators:  []validator.Set{setvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"key": schema.StringAttribute{Required: true, Description: "Public key in authorized_keys format (a trailing comment is allowed and ignored for matching)."},
					"description": schema.StringAttribute{
						Optional:   true,
						Validators: []validator.String{stringvalidator.LengthAtLeast(1)},
						Description: "Free-text description (pgs's `public_keys.name`, shown as the login identity), e.g. which person uses the key. " +
							"Defaults to the key's comment, or `main` when it has none.",
					},
				}},
			},
			"access": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Metadata of the account's `pgs` feature flag. The flag itself always exists (without it the account would have no access to pgs); " +
					"this block only sets its expiry and quotas. Omit it, or leave attributes unset, for the defaults. Other flags of the account are never touched.",
				Attributes: map[string]schema.Attribute{
					"expires_at": schema.StringAttribute{
						Optional: true, Computed: true, Default: stringdefault.StaticString(pgs.DefaultExpiresAt),
						Description: "Expiry as `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` (UTC), stored verbatim. Default `2200-01-01`.",
						Validators:  []validator.String{stringvalidator.RegexMatches(expiresRE, "must be YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")},
					},
					"storage_max":      schema.Int64Attribute{Optional: true, Description: "Total storage quota in bytes. Unset: pgs default (50 MB).", Validators: []validator.Int64{int64validator.AtLeast(1)}},
					"file_max":         schema.Int64Attribute{Optional: true, Description: "Maximum size of one file in bytes. Unset: pgs default (10 MB).", Validators: []validator.Int64{int64validator.AtLeast(1)}},
					"special_file_max": schema.Int64Attribute{Optional: true, Description: "Maximum size of `_headers`, `_redirects` and `_pgs_ignore` in bytes. Unset: pgs default (5 KB).", Validators: []validator.Int64{int64validator.AtLeast(1)}},
				},
			},
			"flag_id": schema.StringAttribute{
				Computed:    true,
				Description: "Id of the account's `pgs` row in feature_flags (null while the row is missing; the plan then shows the `access` drift and apply recreates it).",
			},
			"force_destroy": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Delete the account even if it still has projects. Site files in pgs's object storage are not removed.",
			},
		},
	}
}

func (r *accountResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var set types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("public_keys"), &set)...)
	if resp.Diagnostics.HasError() || set.IsNull() || set.IsUnknown() {
		return
	}
	var elems []keyModel
	resp.Diagnostics.Append(set.ElementsAs(ctx, &elems, false)...)
	seen := map[string]bool{}
	for _, e := range elems {
		if e.Key.IsUnknown() || e.Key.IsNull() {
			continue
		}
		pk, err := pgs.ParseKey(e.Key.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("public_keys"), "Invalid public key", err.Error())
			continue
		}
		if seen[pk.Normalized] {
			resp.Diagnostics.AddAttributeError(path.Root("public_keys"), "Duplicate public key", "The same key is listed more than once: "+e.Key.ValueString())
		}
		seen[pk.Normalized] = true
	}
}

// ModifyPlan rejects, at plan time, a key that another account already owns: either an account in
// pgs's database or another pgs_account in this configuration. The same check runs again when
// applying, so this only moves the failure earlier. It is best effort: when the database cannot be
// queried the plan continues with a warning.
func (r *accountResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if r.store == nil || req.Plan.Raw.IsNull() { // provider not configured yet, or destroying
		return
	}
	var name types.String
	var set types.Set
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("name"), &name)...)
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("public_keys"), &set)...)
	if resp.Diagnostics.HasError() || name.IsUnknown() || name.IsNull() || set.IsUnknown() || set.IsNull() {
		return
	}
	var elems []keyModel
	resp.Diagnostics.Append(set.ElementsAs(ctx, &elems, false)...)
	var keys []pgs.KeyInput
	for _, e := range elems {
		if e.Key.IsUnknown() || e.Key.IsNull() {
			return // not fully known yet; the apply-time check covers it
		}
		pk, err := pgs.ParseKey(e.Key.ValueString())
		if err != nil {
			return // ValidateConfig reports it
		}
		keys = append(keys, pgs.KeyInput{Normalized: pk.Normalized})
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if key, other := r.store.ClaimKeys(name.ValueString(), keys); other != "" {
		resp.Diagnostics.AddAttributeError(path.Root("public_keys"), "Public key used by more than one account",
			fmt.Sprintf("The key %q is listed for both %q and %q. A key can belong to one account only.", key, other, name.ValueString()))
		return
	}
	var ownerID int64
	if !req.State.Raw.IsNull() {
		var id types.String
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("id"), &id)...)
		if n, err := strconv.ParseInt(id.ValueString(), 10, 64); err == nil {
			ownerID = n
		}
	}
	switch err := r.store.CheckKeyConflicts(ctx, ownerID, keys); {
	case err == nil:
	case errors.As(err, new(*pgs.KeyConflictError)):
		resp.Diagnostics.AddAttributeError(path.Root("public_keys"), "Public key already in use",
			err.Error()+"\n\nIf the key is moving between two accounts managed here, remove it from the old account and apply, then add it to the new one.")
	default:
		resp.Diagnostics.AddAttributeWarning(path.Root("public_keys"), "Could not check public keys against pgs", err.Error())
	}
}

func (r *accountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	st, ok := req.ProviderData.(*pgs.Store)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.store = st
}

func storeError(diags *diag.Diagnostics, summary string, err error) {
	detail := err.Error()
	if errors.Is(err, pgs.ErrProtected) {
		detail += "\n\nThe admin account (and anything in protected_accounts) is deliberately outside this provider's control."
	}
	diags.AddError(summary, detail)
}

// stateFrom converts a database account into resource state. prior* carry the config/state values
// so that equivalent representations (key comments, omitted access block) do not show as drift.
func stateFrom(ctx context.Context, acc *pgs.Account, priorKeys types.Set, priorAccess types.Object, force types.Bool) (accountModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	keys, d := keysObject(ctx, acc, priorKeys)
	diags.Append(d...)
	flag := acc.ManagedFlag()
	access, d := accessObject(ctx, flag, priorAccess)
	diags.Append(d...)
	flagID := types.StringNull()
	if flag != nil {
		flagID = types.StringValue(strconv.FormatInt(flag.ID, 10))
	}
	return accountModel{
		ID: types.StringValue(strconv.FormatInt(acc.ID, 10)), Name: types.StringValue(acc.Name), CreatedAt: types.StringValue(acc.CreatedAt),
		PublicKeys: keys, Access: access, FlagID: flagID, ForceDestroy: force,
	}, diags
}

func (r *accountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan accountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keys, comments, d := desiredKeys(ctx, plan.PublicKeys)
	resp.Diagnostics.Append(d...)
	access, d := desiredAccess(ctx, plan.Access)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	acc, err := r.store.Create(ctx, plan.Name.ValueString(), keys, access, comments)
	if err != nil {
		storeError(&resp.Diagnostics, "Cannot create pgs account", err)
		return
	}
	st, d := stateFrom(ctx, acc, plan.PublicKeys, plan.Access, plan.ForceDestroy)
	resp.Diagnostics.Append(d...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, st)...)
	}
}

func (r *accountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state accountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid id in state", err.Error())
		return
	}
	acc, err := r.store.GetByID(ctx, id)
	if err != nil {
		storeError(&resp.Diagnostics, "Cannot read pgs account", err)
		return
	}
	if acc == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	st, d := stateFrom(ctx, acc, state.PublicKeys, state.Access, state.ForceDestroy)
	resp.Diagnostics.Append(d...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, st)...)
	}
}

func (r *accountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state accountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid id in state", err.Error())
		return
	}
	keys, comments, d := desiredKeys(ctx, plan.PublicKeys)
	resp.Diagnostics.Append(d...)
	access, d := desiredAccess(ctx, plan.Access)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	acc, err := r.store.Update(ctx, id, plan.Name.ValueString(), keys, access, comments)
	if err != nil {
		storeError(&resp.Diagnostics, "Cannot update pgs account", err)
		return
	}
	st, d := stateFrom(ctx, acc, plan.PublicKeys, plan.Access, plan.ForceDestroy)
	resp.Diagnostics.Append(d...)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, st)...)
	}
}

func (r *accountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state accountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := strconv.ParseInt(state.ID.ValueString(), 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid id in state", err.Error())
		return
	}
	if err := r.store.Delete(ctx, id, state.ForceDestroy.ValueBool()); err != nil {
		storeError(&resp.Diagnostics, "Cannot delete pgs account", err)
	}
}

func (r *accountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	acc, err := r.store.GetByName(ctx, req.ID)
	if err != nil {
		storeError(&resp.Diagnostics, "Cannot import pgs account", err)
		return
	}
	if acc == nil {
		resp.Diagnostics.AddError("Cannot import pgs account", fmt.Sprintf("no account named %q", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), strconv.FormatInt(acc.ID, 10))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), acc.Name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("force_destroy"), false)...)
}
