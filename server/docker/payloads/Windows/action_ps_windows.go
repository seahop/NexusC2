// server/docker/payloads/Windows/action_ps_windows.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"syscall"
)

// getWindowsSecurityContext returns Windows-specific security context info
func getWindowsSecurityContext() string {
	if threadToken := GetThreadToken(); threadToken != 0 {
		defer syscall.Token(threadToken).Close()
		if user, domain := GetTokenUser(syscall.Handle(threadToken)); user != "" {
			return fmt.Sprintf("[*] Running as: %s\\%s (impersonated)", domain, user)
		}
	}
	return ""
}
