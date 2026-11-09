package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/innoq/terraform-provider-pgs/internal/pgs"
)

var basicObjectOptions = basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true}

type keyModel struct {
	Key         types.String `tfsdk:"key"`
	Description types.String `tfsdk:"description"`
}

type accessModel struct {
	ExpiresAt      types.String `tfsdk:"expires_at"`
	StorageMax     types.Int64  `tfsdk:"storage_max"`
	FileMax        types.Int64  `tfsdk:"file_max"`
	SpecialFileMax types.Int64  `tfsdk:"special_file_max"`
}

var (
	keyAttrTypes = map[string]attr.Type{"key": types.StringType, "description": types.StringType}
	keyObjType   = types.ObjectType{AttrTypes: keyAttrTypes}

	accessAttrTypes = map[string]attr.Type{
		"expires_at":  types.StringType,
		"storage_max": types.Int64Type, "file_max": types.Int64Type, "special_file_max": types.Int64Type,
	}
)

// desiredKeys converts the configured key set. comments maps normalized key -> authorized_keys comment.
func desiredKeys(ctx context.Context, set types.Set) (keys []pgs.KeyInput, comments map[string]string, diags diag.Diagnostics) {
	var elems []keyModel
	diags.Append(set.ElementsAs(ctx, &elems, false)...)
	comments = map[string]string{}
	seen := map[string]bool{}
	for _, e := range elems {
		pk, err := pgs.ParseKey(e.Key.ValueString())
		if err != nil {
			diags.AddError("Invalid public key", err.Error())
			continue
		}
		if seen[pk.Normalized] {
			diags.AddError("Duplicate public key", fmt.Sprintf("The same key appears more than once: %s", e.Key.ValueString()))
			continue
		}
		seen[pk.Normalized] = true
		comments[pk.Normalized] = pk.Comment
		keys = append(keys, pgs.KeyInput{Normalized: pk.Normalized, Description: e.Description.ValueString()})
	}
	return keys, comments, diags
}

func int64Ptr(v types.Int64) *int64 {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	n := v.ValueInt64()
	return &n
}

// desiredAccess returns the wanted content of the pgs flag; an absent access block means defaults.
func desiredAccess(ctx context.Context, obj types.Object) (pgs.AccessInput, diag.Diagnostics) {
	if obj.IsNull() || obj.IsUnknown() {
		return pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil
	}
	var m accessModel
	diags := obj.As(ctx, &m, basicObjectOptions)
	return pgs.AccessInput{
		ExpiresAt: m.ExpiresAt.ValueString(),
		Data:      pgs.FlagData{StorageMax: int64Ptr(m.StorageMax), FileMax: int64Ptr(m.FileMax), SpecialFileMax: int64Ptr(m.SpecialFileMax)},
	}, diags
}

func optInt64(p *int64) types.Int64 {
	if p == nil {
		return types.Int64Null()
	}
	return types.Int64Value(*p)
}

// accessObject renders the pgs flag's metadata. When the flag holds nothing but defaults and the prior
// value was null, it stays null, so an omitted access block never shows up as drift.
//
// A missing flag is rendered as an object whose attributes are all null. That never equals the
// configuration (null, or a block with a default expires_at), so the plan shows the drift and apply recreates the flag.
func accessObject(ctx context.Context, f *pgs.Flag, prior types.Object) (types.Object, diag.Diagnostics) {
	if f == nil {
		return types.ObjectValueFrom(ctx, accessAttrTypes, accessModel{
			ExpiresAt: types.StringNull(), StorageMax: types.Int64Null(), FileMax: types.Int64Null(), SpecialFileMax: types.Int64Null(),
		})
	}
	d := f.Parse()
	if prior.IsNull() && f.ExpiresAt == pgs.DefaultExpiresAt && d.StorageMax == nil && d.FileMax == nil && d.SpecialFileMax == nil {
		return types.ObjectNull(accessAttrTypes), nil
	}
	return types.ObjectValueFrom(ctx, accessAttrTypes, accessModel{
		ExpiresAt:  types.StringValue(f.ExpiresAt),
		StorageMax: optInt64(d.StorageMax), FileMax: optInt64(d.FileMax), SpecialFileMax: optInt64(d.SpecialFileMax),
	})
}

// keysObject builds the public_keys set from the database rows. Keys that already exist in
// prior (config/state) keep the exact string and a null description when that is equivalent,
// so comments and default descriptions never show up as drift.
func keysObject(ctx context.Context, acc *pgs.Account, prior types.Set) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	priorByKey := map[string]keyModel{}
	if !prior.IsNull() && !prior.IsUnknown() {
		var elems []keyModel
		diags.Append(prior.ElementsAs(ctx, &elems, false)...)
		for _, e := range elems {
			if pk, err := pgs.ParseKey(e.Key.ValueString()); err == nil {
				priorByKey[pk.Normalized] = e
			}
		}
	}
	out := make([]keyModel, 0, len(acc.Keys))
	for _, k := range acc.Keys {
		if p, ok := priorByKey[k.PublicKey]; ok {
			m := keyModel{Key: p.Key, Description: types.StringValue(k.Description)}
			if p.Description.IsNull() {
				pk, _ := pgs.ParseKey(p.Key.ValueString())
				if k.Description == pgs.DefaultDescription(pk.Comment) {
					m.Description = types.StringNull()
				}
			}
			out = append(out, m)
			continue
		}
		out = append(out, keyModel{Key: types.StringValue(k.PublicKey), Description: types.StringValue(k.Description)})
	}
	set, d := types.SetValueFrom(ctx, keyObjType, out)
	diags.Append(d...)
	return set, diags
}
