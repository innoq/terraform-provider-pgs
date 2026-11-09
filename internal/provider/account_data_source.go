package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/innoq/terraform-provider-pgs/internal/pgs"
)

var (
	_ datasource.DataSource              = (*accountDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*accountDataSource)(nil)
)

type accountDataSource struct{ store *pgs.Store }

func NewAccountDataSource() datasource.DataSource { return &accountDataSource{} }

type accountDataModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	CreatedAt  types.String `tfsdk:"created_at"`
	PublicKeys types.Set    `tfsdk:"public_keys"`
	Access     types.Object `tfsdk:"access"`
}

func (d *accountDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_account"
}

func (d *accountDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads an existing pgs account by name. The admin account cannot be read.",
		Attributes: map[string]schema.Attribute{
			"name":       schema.StringAttribute{Required: true},
			"id":         schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"public_keys": schema.SetNestedAttribute{Computed: true, NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
				"key":         schema.StringAttribute{Computed: true},
				"description": schema.StringAttribute{Computed: true},
			}}},
			"access": schema.SingleNestedAttribute{Computed: true, Description: "Metadata of the account's `pgs` feature flag (null if the account has none).", Attributes: map[string]schema.Attribute{
				"expires_at":       schema.StringAttribute{Computed: true},
				"storage_max":      schema.Int64Attribute{Computed: true},
				"file_max":         schema.Int64Attribute{Computed: true},
				"special_file_max": schema.Int64Attribute{Computed: true},
			}},
		},
	}
}

func (d *accountDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	st, ok := req.ProviderData.(*pgs.Store)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	d.store = st
}

func (d *accountDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg accountDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	acc, err := d.store.GetByName(ctx, cfg.Name.ValueString())
	if err != nil {
		storeError(&resp.Diagnostics, "Cannot read pgs account", err)
		return
	}
	if acc == nil {
		resp.Diagnostics.AddError("pgs account not found", fmt.Sprintf("no account named %q", cfg.Name.ValueString()))
		return
	}
	keys, diags := keysObject(ctx, acc, types.SetNull(keyObjType))
	resp.Diagnostics.Append(diags...)
	access := types.ObjectNull(accessAttrTypes)
	if f := acc.ManagedFlag(); f != nil {
		access, diags = accessObject(ctx, f, types.ObjectNull(accessAttrTypes))
		resp.Diagnostics.Append(diags...)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, accountDataModel{
		ID: types.StringValue(strconv.FormatInt(acc.ID, 10)), Name: types.StringValue(acc.Name), CreatedAt: types.StringValue(acc.CreatedAt),
		PublicKeys: keys, Access: access,
	})...)
}
