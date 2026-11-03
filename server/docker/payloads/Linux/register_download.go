//go:build linux && (!feature_modular || feature_download)

package main

func init() {
	registerFeature(CmdDownload, wrapCommand(&FM{}))
}
