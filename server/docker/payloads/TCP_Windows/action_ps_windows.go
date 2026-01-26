// server/docker/payloads/Windows/action_ps_windows.go
//go:build windows
// +build windows

package main

import (
	"sync"
	"syscall"
)

// Template indices for PS Windows - must match server's common.go
const (
	idxPsRunningAs    = 186
	idxPsBackslash    = 187
	idxPsImpersonated = 188
)

// Global ps template storage for Windows-specific functions
var (
	psWindowsTemplate   []string
	psWindowsTemplateMu sync.RWMutex
)

// SetPsWindowsTemplate stores the ps template for Windows helpers
func SetPsWindowsTemplate(templates []string) {
	psWindowsTemplateMu.Lock()
	psWindowsTemplate = templates
	psWindowsTemplateMu.Unlock()
}

// pswTpl retrieves a ps windows template string by index
func pswTpl(idx int) string {
	psWindowsTemplateMu.RLock()
	defer psWindowsTemplateMu.RUnlock()
	if psWindowsTemplate != nil && idx < len(psWindowsTemplate) {
		return psWindowsTemplate[idx]
	}
	return ""
}

// Convenience functions for ps windows template values
func psRunningAs() string    { return pswTpl(idxPsRunningAs) }
func psBackslash() string    { return pswTpl(idxPsBackslash) }
func psImpersonated() string { return pswTpl(idxPsImpersonated) }

// getWindowsSecurityContext returns Windows-specific security context info
func getWindowsSecurityContext() string {
	if threadToken := GetThreadToken(); threadToken != 0 {
		defer syscall.Token(threadToken).Close()
		if user, domain := GetTokenUser(syscall.Handle(threadToken)); user != "" {
			return psRunningAs() + domain + psBackslash() + user + psImpersonated()
		}
	}
	return ""
}
