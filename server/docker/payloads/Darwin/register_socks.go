//go:build darwin && (!feature_modular || feature_socks)

package main

func init() {
	registerFeature(CmdSocks, wrapCommand(&ProxyMsg{}))
	registerFeature(CmdSocksHTTP, wrapCommand(GetSocksHTTPHandler()))
}
