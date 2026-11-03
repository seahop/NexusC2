//go:build windows && (!feature_modular || feature_download)

package main

func init() {
	registerFeature(CmdDownload, wrapCommand(&FM{}))
}
