//go:build linux && (!feature_modular || feature_persist)

package main

func init() {
	registerFeature(CmdPersist, wrapCommand(&SetupMsg{}))
}
