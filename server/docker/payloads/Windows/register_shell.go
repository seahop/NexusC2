//go:build windows && (!feature_modular || feature_shell)

package main

func init() {
	registerFeature(CmdShell, wrapCommand(&ExecMsg{}))
}
