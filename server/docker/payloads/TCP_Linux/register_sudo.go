//go:build linux && (!feature_modular || feature_sudo)

package main

func init() {
	registerFeature(CmdSudoSession, wrapCommand(&ElevMsg{}))
}
