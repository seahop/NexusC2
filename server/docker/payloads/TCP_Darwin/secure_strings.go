// server/docker/payloads/TCP_Darwin/secure_strings.go
//go:build darwin
// +build darwin

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

// SecureBytes wraps []byte with zeroing capability for sensitive data
type SecureBytes struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecureBytes creates a SecureBytes from a string
func NewSecureBytes(s string) *SecureBytes {
	return &SecureBytes{data: []byte(s)}
}

// String returns the string value
func (sb *SecureBytes) String() string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.data == nil {
		return ""
	}
	return string(sb.data)
}

// Bytes returns a copy of the byte data
func (sb *SecureBytes) Bytes() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	if sb.data == nil {
		return nil
	}
	cpy := make([]byte, len(sb.data))
	copy(cpy, sb.data)
	return cpy
}

// Zero securely wipes the data
func (sb *SecureBytes) Zero() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	if sb.data != nil {
		ZeroBytes(sb.data)
		sb.data = nil
	}
}

// SecureStringArray manages an array of []byte that can be zeroed
type SecureStringArray struct {
	data [][]byte
	mu   sync.RWMutex
}

// NewSecureStringArray creates a SecureStringArray from a string slice
func NewSecureStringArray(strs []string) *SecureStringArray {
	arr := &SecureStringArray{
		data: make([][]byte, len(strs)),
	}
	for i, s := range strs {
		arr.data[i] = []byte(s)
	}
	return arr
}

// Get retrieves a string at the given index
func (sa *SecureStringArray) Get(idx int) string {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	if sa.data == nil || idx < 0 || idx >= len(sa.data) {
		return ""
	}
	return string(sa.data[idx])
}

// Set updates a string at the given index
func (sa *SecureStringArray) Set(idx int, s string) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.data == nil || idx < 0 || idx >= len(sa.data) {
		return
	}
	// Zero old value first
	ZeroBytes(sa.data[idx])
	sa.data[idx] = []byte(s)
}

// Zero securely wipes all data in the array
func (sa *SecureStringArray) Zero() {
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
func (sa *SecureStringArray) Len() int {
	sa.mu.RLock()
	defer sa.mu.RUnlock()
	if sa.data == nil {
		return 0
	}
	return len(sa.data)
}

// SecureTemplate provides secure storage for template data with memory zeroing
type SecureTemplate struct {
	Version   int
	Type      int
	templates *SecureStringArray
	params    *SecureStringArray
}

// NewSecureTemplateFromSlices creates a SecureTemplate from version, type, and string slices
func NewSecureTemplateFromSlices(version, typ int, templates, params []string) *SecureTemplate {
	return &SecureTemplate{
		Version:   version,
		Type:      typ,
		templates: NewSecureStringArray(templates),
		params:    NewSecureStringArray(params),
	}
}

// Get retrieves a template string by index
func (st *SecureTemplate) Get(idx int) string {
	if st == nil || st.templates == nil {
		return ""
	}
	return st.templates.Get(idx)
}

// GetParam retrieves a param string by index
func (st *SecureTemplate) GetParam(idx int) string {
	if st == nil || st.params == nil {
		return ""
	}
	return st.params.Get(idx)
}

// TemplateLen returns the number of templates
func (st *SecureTemplate) TemplateLen() int {
	if st == nil || st.templates == nil {
		return 0
	}
	return st.templates.Len()
}

// Zero securely wipes all template data
func (st *SecureTemplate) Zero() {
	if st == nil {
		return
	}
	if st.templates != nil {
		st.templates.Zero()
	}
	if st.params != nil {
		st.params.Zero()
	}
}
