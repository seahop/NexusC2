// server/docker/payloads/Windows/action_download_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
)

// getDownloadSecurityContext returns Windows-specific security context info for downloads
func getDownloadSecurityContext() string {
	if threadToken := GetThreadToken(); threadToken != 0 {
		defer syscall.Token(threadToken).Close()
		if user, domain := GetTokenUser(syscall.Handle(threadToken)); user != "" {
			return fmt.Sprintf("Downloading as %s\\%s\n", domain, user)
		}
	}
	return ""
}
