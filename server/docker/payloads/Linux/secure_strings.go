// server/docker/payloads/Linux/secure_strings.go
//go:build linux
// +build linux

package main

import (
	"runtime"
	"sync"
)

// ZeroBytes securely wipes a byte slice by overwriting with zeros
func ZeroBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Prevent compiler from optimizing away the zeroing
	runtime.KeepAlive(b)
}

// SafeBytes wraps []byte with zeroing capability for sensitive data
type SafeBytes struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecureBytes creates a SafeBytes from a string
func NewSecureBytes(s string) *SafeBytes {
	return &SafeBytes{data: []byte(s)}
}

// String returns the string value
func (sb *SafeBytes) String() string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.data == nil {
		return ""
	}
	return string(sb.data)
}

// Bytes returns a copy of the byte data
func (sb *SafeBytes) Bytes() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.data == nil {
		return nil
	}
	cpy := make([]byte, len(sb.data))
	copy(cpy, sb.data)
	return cpy
}

// zero securely wipes the data
func (sb *SafeBytes) zero() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.data != nil {
		ZeroBytes(sb.data)
		sb.data = nil
	}
}

// SafeStrArray manages an array of []byte that can be zeroed
type SafeStrArray struct {
	data [][]byte
	mu   sync.RWMutex
}

// NewSecureStringArray creates a SafeStrArray from a string slice
func NewSecureStringArray(strs []string) *SafeStrArray {
	arr := &SafeStrArray{
		data: make([][]byte, len(strs)),
	}
	for i, s := range strs {
		arr.data[i] = []byte(s)
	}
	return arr
}

// Get retrieves a string at the given index
func (sa *SafeStrArray) Get(idx int) string {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	if sa.data == nil || idx < 0 || idx >= len(sa.data) {
		return ""
	}
	return string(sa.data[idx])
}

// Set updates a string at the given index
func (sa *SafeStrArray) Set(idx int, s string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.data == nil || idx < 0 || idx >= len(sa.data) {
		return
	}
	// zero old value first
	ZeroBytes(sa.data[idx])
	sa.data[idx] = []byte(s)
}

// zero securely wipes all data in the array
func (sa *SafeStrArray) zero() {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.data != nil {
		for i := range sa.data {
			ZeroBytes(sa.data[i])
		}
		sa.data = nil
	}
}

// Len returns the length of the array
func (sa *SafeStrArray) Len() int {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	if sa.data == nil {
		return 0
	}
	return len(sa.data)
}

// SafeTemplate provides secure storage for template data with memory zeroing
type SafeTemplate struct {
	Version   int
	Type      int
	templates *SafeStrArray
	params    *SafeStrArray
}

// NewSecureTemplateFromSlices creates a SafeTemplate from version, type, and string slices
func NewSecureTemplateFromSlices(version, typ int, templates, params []string) *SafeTemplate {
	return &SafeTemplate{
		Version:   version,
		Type:      typ,
		templates: NewSecureStringArray(templates),
		params:    NewSecureStringArray(params),
	}
}

// Get retrieves a template string by index
func (st *SafeTemplate) Get(idx int) string {
	if st == nil || st.templates == nil {
		return ""
	}
	return st.templates.Get(idx)
}

// getParam retrieves a param string by index
func (st *SafeTemplate) getParam(idx int) string {
	if st == nil || st.params == nil {
		return ""
	}
	return st.params.Get(idx)
}

// templateLen returns the number of templates
func (st *SafeTemplate) templateLen() int {
	if st == nil || st.templates == nil {
		return 0
	}
	return st.templates.Len()
}

// zero securely wipes all template data
func (st *SafeTemplate) zero() {
	if st == nil {
		return
	}
	if st.templates != nil {
		st.templates.zero()
	}
	if st.params != nil {
		st.params.zero()
	}
}
