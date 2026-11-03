//go:build darwin && (!feature_modular || feature_persist)

package main

func init() {
	registerFeature(CmdPersist, wrapCommand(&SetupMsg{}))
}
