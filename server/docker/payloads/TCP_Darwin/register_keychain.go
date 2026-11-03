//go:build darwin && (!feature_modular || feature_keychain)

package main

func init() {
	registerFeature(CmdKeychain, wrapCommand(&SecStoreMsg{}))
}
