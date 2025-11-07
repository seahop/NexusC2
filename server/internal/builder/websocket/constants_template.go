package builder

const constantsTemplate = `package main

// Auto-generated configuration - DO NOT EDIT
// Generated at: %s
// Listener: %s
// Target OS: %s
// Target Arch: %s

import "fmt"

// Connection Configuration
const (
	clientID    = "%s"
	secret      = "%s"
	xorKey      = "%s"
	serverIP    = "%s"
	serverPort  = %d
	protocol    = "%s"
	
	// HTTP Configuration
	userAgent   = "%s"
	contentType = "%s"
	getRoute    = "%s"
	postRoute   = "%s"
	getMethod   = "%s"  // Custom HTTP method for GET operations
	postMethod  = "%s"  // Custom HTTP method for POST operations
	
	// Parameter names
	getClientIDName    = "%s"
	getClientIDFormat  = "%s"
	postClientIDName   = "%s"
	postClientIDFormat = "%s"
	postSecretName     = "%s"
	postSecretFormat   = "%s"
	
	// Timing
	sleepTime   = %d
	jitterTime  = %d
)

// RSA Public Key
const publicKeyPEM = ` + "`%s`" + `

// Custom Headers
var customHeaders = map[string]string{
%s
}

// Helper function for compatibility with existing code
func getDecryptedValue(key string) string {
	values := map[string]string{
		"CLIENT_ID":           clientID,
		"SECRET":              secret,
		"XOR_KEY":             xorKey,
		"IP":                  serverIP,
		"PORT":                fmt.Sprintf("%%d", serverPort),
		"PROTOCOL":            protocol,
		"USER_AGENT":          userAgent,
		"CONTENT_TYPE":        contentType,
		"GET_ROUTE":           getRoute,
		"POST_ROUTE":          postRoute,
		"GET_METHOD":          getMethod,
		"POST_METHOD":         postMethod,
		"PUBLIC_KEY":          publicKeyPEM,
		"GET_CLIENT_ID_NAME":  getClientIDName,
		"GET_CLIENT_ID_FORMAT": getClientIDFormat,
		"POST_CLIENT_ID_NAME":  postClientIDName,
		"POST_CLIENT_ID_FORMAT": postClientIDFormat,
		"POST_SECRET_NAME":    postSecretName,
		"POST_SECRET_FORMAT":  postSecretFormat,
		"SLEEP":               fmt.Sprintf("%%d", sleepTime),
		"JITTER":              fmt.Sprintf("%%d", jitterTime),
	}
	
	// Also check the XOR-encrypted versions (for compatibility)
	encryptedKeys := map[string]string{
		"Public Key":   publicKeyPEM,
		"Secret":       secret,
		"Protocol":     protocol,
		"IP":           serverIP,
		"Port":         fmt.Sprintf("%%d", serverPort),
		"User Agent":   userAgent,
		"Content Type": contentType,
		"Get Method":   getMethod,
		"Post Method":  postMethod,
		"Custom Headers": formatCustomHeaders(),
		"Get Route":    getRoute,
		"Post Route":   postRoute,
	}
	
	if val, ok := values[key]; ok {
		return val
	}
	
	if val, ok := encryptedKeys[key]; ok {
		return val
	}
	
	return ""
}

func formatCustomHeaders() string {
	result := "{"
	first := true
	for k, v := range customHeaders {
		if !first {
			result += ","
		}
		result += fmt.Sprintf("\"%%s\":\"%%s\"", k, v)
		first = false
	}
	result += "}"
	return result
}

// XOR decrypt function (no-op since values are already decrypted)
func xorDecrypt(input string, key string) string {
	// In the project export, values are already in plaintext
	// This function exists for compatibility with the original code
	return input
}
`
