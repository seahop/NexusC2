//go:build linux && (!feature_modular || feature_link)

package main

func init() {
	registerFeature(CmdLink, wrapCommand(&RM{}))
	registerFeature(CmdUnlink, wrapCommand(&DM{}))
	registerFeature(CmdLinks, wrapCommand(&RLM{}))
}
