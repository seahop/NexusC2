// server/docker/payloads/shared/network_aware_stub.go
//go:build linux
// +build linux

package main

import "os"

// Non-Windows stubs - just pass through to normal OS functions

func NetworkAwareStatFile(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func NetworkAwareReadDir(path string) ([]os.DirEntry, error) {
	return os.ReadDir(path)
}

func NetworkAwareOpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func NetworkAwareRemove(path string) error {
	return os.Remove(path)
}

func NetworkAwareRemoveAll(path string) error {
	return os.RemoveAll(path)
}

func NetworkAwareMkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// IsNetworkPath always returns false on non-Windows systems
func IsNetworkPath(path string) bool {
	return false
}

// PrepareNetworkOperation always returns empty string on non-Windows systems
func PrepareNetworkOperation(path string) string {
	return ""
}
