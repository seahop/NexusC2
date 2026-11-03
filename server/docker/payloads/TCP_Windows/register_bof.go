//go:build windows && (!feature_modular || feature_bof)

package main

func init() {
	registerFeature(CmdBof, wrapCommand(&TaskRunMsg{}))
	registerFeature(CmdBofAsync, wrapCommand(&AsyncTaskMsg{}))
	registerFeature(CmdBofJobs, wrapCommand(&JobListMsg{}))
	registerFeature(CmdBofOutput, wrapCommand(&TaskOutputMsg{}))
	registerFeature(CmdBofKill, wrapCommand(&JobStopMsg{}))
}
