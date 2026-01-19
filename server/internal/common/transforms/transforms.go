// internal/common/transforms/transforms.go
// Package transforms provides data transformation functions for malleable HTTP profiles.
// Transforms can be chained together and are reversible for server-side extraction.
package transforms

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// TransformType represents the type of transformation
type TransformType string

const (
	// Encoding transforms
	TransformBase64    TransformType = "base64"
	TransformBase64URL TransformType = "base64url"
	TransformHex       TransformType = "hex"
	TransformGzip      TransformType = "gzip"
	TransformNetBIOS   TransformType = "netbios"

	// Masking transforms
	TransformXOR TransformType = "xor"

	// Padding transforms
	TransformPrepend       TransformType = "prepend"
	TransformAppend        TransformType = "append"
	TransformRandomPrepend TransformType = "random_prepend"
	TransformRandomAppend  TransformType = "random_append"
)

// Charset options for random transforms
type Charset string

const (
	CharsetNumeric      Charset = "numeric"
	CharsetAlpha        Charset = "alpha"
	CharsetAlphanumeric Charset = "alphanumeric"
	CharsetHex          Charset = "hex"
)

// Character sets for random generation
var charsets = map[Charset]string{
	CharsetNumeric:      "0123456789",
	CharsetAlpha:        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	CharsetAlphanumeric: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	CharsetHex:          "0123456789abcdef",
}

// Transform represents a single transformation configuration
type Transform struct {
	Type    TransformType
	Value   string // For prepend/append: static string. For XOR: the key
	Length  int    // For random_prepend/random_append: number of chars
	Charset Charset
}

// TransformResult contains the result of a transformation chain
// along with metadata needed for reversal (e.g., random padding lengths)
type TransformResult struct {
	Data []byte

	// Metadata for reversal - stored as header/cookie for server extraction
	PrependLength int // Length of random prepend (if used)
	AppendLength  int // Length of random append (if used)
}

// =============================================================================
// FORWARD TRANSFORMS (Agent -> Server)
// =============================================================================

// Apply applies a chain of transforms to data in order
func Apply(data []byte, transforms []Transform) (*TransformResult, error) {
	result := &TransformResult{Data: data}

	for _, t := range transforms {
		var err error
		switch t.Type {
		case TransformBase64:
			result.Data = encodeBase64(result.Data)
		case TransformBase64URL:
			result.Data = encodeBase64URL(result.Data)
		case TransformHex:
			result.Data = encodeHex(result.Data)
		case TransformGzip:
			result.Data, err = encodeGzip(result.Data)
		case TransformNetBIOS:
			result.Data = encodeNetBIOS(result.Data)
		case TransformXOR:
			result.Data = applyXOR(result.Data, []byte(t.Value))
		case TransformPrepend:
			result.Data = prepend(result.Data, []byte(t.Value))
		case TransformAppend:
			result.Data = appendData(result.Data, []byte(t.Value))
		case TransformRandomPrepend:
			padding := generateRandom(t.Length, t.Charset)
			result.Data = prepend(result.Data, padding)
			result.PrependLength = t.Length
		case TransformRandomAppend:
			padding := generateRandom(t.Length, t.Charset)
			result.Data = appendData(result.Data, padding)
			result.AppendLength = t.Length
		default:
			return nil, fmt.Errorf("unknown transform type: %s", t.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("transform %s failed: %v", t.Type, err)
		}
	}

	return result, nil
}

// =============================================================================
// REVERSE TRANSFORMS (Server extracts original data)
// =============================================================================

// Reverse applies transforms in reverse order to extract original data
// prependLen and appendLen should be provided if random padding was used
func Reverse(data []byte, transforms []Transform, prependLen, appendLen int) ([]byte, error) {
	result := data

	// Apply transforms in reverse order
	for i := len(transforms) - 1; i >= 0; i-- {
		t := transforms[i]
		var err error

		switch t.Type {
		case TransformBase64:
			result, err = decodeBase64(result)
		case TransformBase64URL:
			result, err = decodeBase64URL(result)
		case TransformHex:
			result, err = decodeHex(result)
		case TransformGzip:
			result, err = decodeGzip(result)
		case TransformNetBIOS:
			result, err = decodeNetBIOS(result)
		case TransformXOR:
			result = applyXOR(result, []byte(t.Value)) // XOR is its own inverse
		case TransformPrepend:
			result = stripPrepend(result, len(t.Value))
		case TransformAppend:
			result = stripAppend(result, len(t.Value))
		case TransformRandomPrepend:
			// Use provided length or fall back to config length
			length := prependLen
			if length == 0 {
				length = t.Length
			}
			result = stripPrepend(result, length)
		case TransformRandomAppend:
			// Use provided length or fall back to config length
			length := appendLen
			if length == 0 {
				length = t.Length
			}
			result = stripAppend(result, length)
		default:
			return nil, fmt.Errorf("unknown transform type: %s", t.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("reverse transform %s failed: %v", t.Type, err)
		}
	}

	return result, nil
}

// =============================================================================
// ENCODING TRANSFORMS
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
// 'a' = 0, 'b' = 1, ... 'p' = 15
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
		return nil, fmt.Errorf("netbios data must have even length")
	}
	result := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		high := data[i] - 'a'
		low := data[i+1] - 'a'
		if high > 15 || low > 15 {
			return nil, fmt.Errorf("invalid netbios character at position %d", i)
		}
		result[i/2] = (high << 4) | low
	}
	return result, nil
}

// =============================================================================
// MASKING TRANSFORMS
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
// PADDING TRANSFORMS
// =============================================================================

func prepend(data []byte, prefix []byte) []byte {
	result := make([]byte, len(prefix)+len(data))
	copy(result, prefix)
	copy(result[len(prefix):], data)
	return result
}

func appendData(data []byte, suffix []byte) []byte {
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

func generateRandom(length int, charset Charset) []byte {
	if length <= 0 {
		return []byte{}
	}

	chars := charsets[charset]
	if chars == "" {
		chars = charsets[CharsetAlphanumeric] // default
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

// ParseOutput parses an output specification like "header:X-Request-ID" or "cookie:session"
// Returns the location type and name
func ParseOutput(output string) (locationType, name string) {
	parts := strings.SplitN(output, ":", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], parts[1]
}

// ValidateTransform validates a transform configuration
func ValidateTransform(t Transform) error {
	switch t.Type {
	case TransformBase64, TransformBase64URL, TransformHex, TransformGzip, TransformNetBIOS:
		// No additional config needed
		return nil

	case TransformXOR:
		if t.Value == "" {
			return fmt.Errorf("xor transform requires a 'value' (key)")
		}
		return nil

	case TransformPrepend, TransformAppend:
		if t.Value == "" {
			return fmt.Errorf("%s transform requires a 'value'", t.Type)
		}
		return nil

	case TransformRandomPrepend, TransformRandomAppend:
		if t.Length <= 0 {
			return fmt.Errorf("%s transform requires a positive 'length'", t.Type)
		}
		if t.Charset != "" && charsets[t.Charset] == "" {
			return fmt.Errorf("invalid charset '%s', must be: numeric, alpha, alphanumeric, or hex", t.Charset)
		}
		return nil

	default:
		return fmt.Errorf("unknown transform type: %s", t.Type)
	}
}

// ValidateOutput validates an output specification
func ValidateOutput(output string) error {
	locationType, name := ParseOutput(output)

	switch locationType {
	case "body":
		return nil
	case "header", "cookie", "query":
		if name == "" {
			return fmt.Errorf("%s output requires a name (e.g., '%s:name')", locationType, locationType)
		}
		return nil
	case "uri_append":
		return nil
	default:
		return fmt.Errorf("invalid output location '%s', must be: body, header:<name>, cookie:<name>, query:<name>, or uri_append", locationType)
	}
}

// TransformChainToString returns a human-readable description of a transform chain
func TransformChainToString(transforms []Transform) string {
	if len(transforms) == 0 {
		return "(no transforms)"
	}

	var parts []string
	for _, t := range transforms {
		switch t.Type {
		case TransformBase64, TransformBase64URL, TransformHex, TransformGzip, TransformNetBIOS:
			parts = append(parts, string(t.Type))
		case TransformXOR:
			parts = append(parts, fmt.Sprintf("xor(key=%q)", t.Value))
		case TransformPrepend:
			parts = append(parts, fmt.Sprintf("prepend(%q)", t.Value))
		case TransformAppend:
			parts = append(parts, fmt.Sprintf("append(%q)", t.Value))
		case TransformRandomPrepend:
			parts = append(parts, fmt.Sprintf("random_prepend(%d, %s)", t.Length, t.Charset))
		case TransformRandomAppend:
			parts = append(parts, fmt.Sprintf("random_append(%d, %s)", t.Length, t.Charset))
		}
	}
	return strings.Join(parts, " -> ")
}
