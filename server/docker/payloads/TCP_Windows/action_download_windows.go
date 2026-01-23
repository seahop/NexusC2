// server/docker/payloads/Windows/action_download_windows.go
//go:build windows
// +build windows

package main

import (
	"syscall"
)

// Download Windows strings (constructed to avoid static signatures)
var (
	dlAsPrefix    = string([]byte{0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x73, 0x20}) // Downloading as
	dlBackslash   = string([]byte{0x5c})                                                                                     // \
	dlNewline     = string([]byte{0x0a})                                                                                     // \n
)

// getDownloadSecurityContext returns Windows-specific security context info for downloads
func getDownloadSecurityContext() string {
	if threadToken := GetThreadToken(); threadToken != 0 {
		defer syscall.Token(threadToken).Close()
		if user, domain := GetTokenUser(syscall.Handle(threadToken)); user != "" {
			return dlAsPrefix + domain + dlBackslash + user + dlNewline
		}
	}
	return ""
}
