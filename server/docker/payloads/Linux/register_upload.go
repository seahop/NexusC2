//go:build linux && (!feature_modular || feature_upload)

package main

func init() {
	registerFeature(CmdUpload, wrapCommand(&SendMsg{}))
}
