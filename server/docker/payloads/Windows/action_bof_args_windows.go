// server/docker/payloads/Windows/action_bof_args_windows.go
//go:build windows
// +build windows

package main

// parseBOFArgumentsPlatform uses the lighthouse package to pack arguments on Windows
func parseBOFArgumentsPlatform(args []string) ([]byte, error) {
	return PackArgs(args)
}
