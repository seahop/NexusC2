//go:build windows && (!feature_modular || feature_token)

package main

func init() {
	registerFeature(CmdToken, wrapCommand(&CredMsg{}))
	registerFeature(CmdRev2self, wrapCommand(&AuthResetMsg{}))
}
