//go:build windows && (!feature_modular || feature_assembly)

package main

func init() {
	registerFeature(CmdInlineAssembly, wrapCommand(&NativeRunMsg{}))
	registerFeature(CmdInlineAssemblyAsync, wrapCommand(&NativeAsyncMsg{}))
	registerFeature(CmdInlineAssemblyJobs, wrapCommand(&NativeJobsMsg{}))
	registerFeature(CmdInlineAssemblyOutput, wrapCommand(&NativeOutputMsg{}))
	registerFeature(CmdInlineAssemblyKill, wrapCommand(&NativeStopMsg{}))
	registerFeature(CmdInlineAssemblyJobsClean, wrapCommand(&NativeCleanMsg{}))
	registerFeature(CmdInlineAssemblyJobsStats, wrapCommand(&NativeStatsMsg{}))
}
