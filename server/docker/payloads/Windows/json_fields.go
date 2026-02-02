// server/docker/payloads/Windows/json_fields.go
//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"os"
)

// JSON field names - injected at build time via ldflags (XOR encrypted)
// These are decrypted in getEnv.go init()
var (
	// Command/Response fields
	jfCT string // CommandType
	jfCO string // Command
	jfCI string // CommandID
	jfCB string // CommandDBID
	jfAI string // AgentID
	jfFN string // Filename
	jfOF string // OriginalFilename
	jfRP string // RemotePath
	jfCC string // CurrentChunk
	jfTC string // TotalChunks
	jfDA string // Data
	jfAR string // Arguments
	jfTS string // Timestamp
	jfJI string // JobID
	jfOU string // Output
	jfEC string // ExitCode
	jfER string // Error

	// Template fields (used for server templates)
	jfV   string // Version
	jfT   string // Type
	jfTPL string // Templates
	jfP   string // Params

	// BOF-specific fields
	jfBD string // BOFData
	jfCD string // ChunkData

	// Handshake/SystemInfo fields
	jfST string // Status
	jfNC string // NewClientID
	jfSI string // SecretsInitialized
	jfSG string // Signature
	jfSD string // Seed
	jfCT2 string // CommsTemplate (ct is taken, use ct2)
	jfET string // ExecReqTemplate
	jfMD string // Metadata
)

// MarshalJSON implements custom JSON marshaling for CommandResponse
// Uses dynamically-injected field names instead of struct tags
func (r *CommandResponse) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Only include non-empty fields
	if r.Command != "" {
		m[jfCO] = r.Command
	}
	if r.CommandID != "" {
		m[jfCI] = r.CommandID
	}
	if r.CommandDBID != 0 {
		m[jfCB] = r.CommandDBID
	}
	if r.AgentID != "" {
		m[jfAI] = r.AgentID
	}
	if r.Filename != "" {
		m[jfFN] = r.Filename
	}
	if r.RemotePath != "" {
		m[jfRP] = r.RemotePath
	}
	if r.CurrentChunk != 0 {
		m[jfCC] = r.CurrentChunk
	}
	if r.TotalChunks != 0 {
		m[jfTC] = r.TotalChunks
	}
	if r.Data != "" {
		m[jfDA] = r.Data
	}
	if r.Output != "" {
		m[jfOU] = r.Output
	}
	if r.Error != "" {
		m[jfER] = r.Error
	}
	m[jfEC] = r.ExitCode
	if r.Timestamp != "" {
		m[jfTS] = r.Timestamp
	}
	if r.JobID != "" {
		m[jfJI] = r.JobID
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for Command
// Accepts dynamically-injected field names
func (c *Command) UnmarshalJSON(data []byte) error {
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
	c.CommandType = getInt(jfCT, "ct")
	c.Command = getString(jfCO, "co")
	c.CommandID = getString(jfCI, "ci")
	c.CommandDBID = getInt(jfCB, "cb")
	c.AgentID = getString(jfAI, "ai")
	c.Filename = getString(jfFN, "fn")
	c.OriginalFilename = getString(jfOF, "of")
	c.RemotePath = getString(jfRP, "rp")
	c.CurrentChunk = getInt(jfCC, "cc")
	c.TotalChunks = getInt(jfTC, "tc")
	c.Data = getString(jfDA, "data")
	c.Arguments = getString(jfAR, "ar")
	c.Timestamp = getString(jfTS, "ts")
	c.JobID = getString(jfJI, "ji")

	return nil
}

// GetJSONFieldMapping returns the current field name mapping
// Maps randomized field names (keys) to standard field names (values)
// Server uses this to translate agent responses back to standard names
func GetJSONFieldMapping() map[string]string {
	return map[string]string{
		jfCT: "ct",
		jfCO: "co",
		jfCI: "ci",
		jfCB: "cb",
		jfAI: "ai",
		jfFN: "fn",
		jfOF: "of",
		jfRP: "rp",
		jfCC: "cc",
		jfTC: "tc",
		jfDA: "data",
		jfAR: "ar",
		jfTS: "ts",
		jfJI: "ji",
		jfOU: "ou",
		jfEC: "ec",
		jfER: "error",
	}
}

// initJSONFields validates that all JSON field names were injected at build time.
// No fallback defaults - if ldflags injection failed, the payload exits immediately.
// Called from init() in getEnv.go after decryption.
func initJSONFields() {
	// Validate all fields were injected - no fallbacks to fingerprintable defaults
	if jfCT == "" || jfCO == "" || jfCI == "" || jfCB == "" ||
		jfAI == "" || jfFN == "" || jfOF == "" || jfRP == "" ||
		jfCC == "" || jfTC == "" || jfDA == "" || jfAR == "" ||
		jfTS == "" || jfJI == "" || jfOU == "" || jfEC == "" ||
		jfER == "" || jfV == "" || jfT == "" || jfTPL == "" ||
		jfP == "" || jfBD == "" || jfCD == "" || jfST == "" ||
		jfNC == "" || jfSI == "" || jfSG == "" || jfSD == "" ||
		jfCT2 == "" || jfET == "" || jfMD == "" {
		os.Exit(1)
	}
}
