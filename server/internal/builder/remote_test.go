package builder

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRemoteBuilder_Build(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert, caCertPEM := genCA(t)
	serverKey, serverCert := genCert(t, caCert, caKey, true)
	clientKey, clientCert := genCert(t, caCert, caKey, false)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	binaryContent := []byte("fake-binary-content-12345")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/build" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			EnvVars    []string `json:"env_vars"`
			BinaryName string   `json:"binary_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.BinaryName == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "binary_name required"})
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(binaryContent)))
		w.Write(binaryContent)
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	writeFile(t, filepath.Join(dir, "ca.crt"), caCertPEM)
	writeKeyFile(t, filepath.Join(dir, "client.crt"), clientCert)
	writeECKeyFile(t, filepath.Join(dir, "client.key"), clientKey)

	os.MkdirAll("/shared", 0755)

	cfg := &RemoteConfig{
		Address:    server.URL,
		CACert:     filepath.Join(dir, "ca.crt"),
		ClientCert: filepath.Join(dir, "client.crt"),
		ClientKey:  filepath.Join(dir, "client.key"),
		Timeout:    "30s",
	}

	rb, err := NewRemoteBuilder(cfg)
	if err != nil {
		t.Fatalf("NewRemoteBuilder failed: %v", err)
	}

	// Override output path to use temp dir
	origBuild := rb.Build
	_ = origBuild

	result, err := rb.Build(context.Background(), &BuildRequest{
		EnvVars:    []string{"OS=linux", "ARCH=amd64"},
		BinaryName: "test_payload",
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if result.BinaryPath != "/shared/test_payload" {
		t.Errorf("unexpected binary path: %s", result.BinaryPath)
	}

	data, err := os.ReadFile(result.BinaryPath)
	if err != nil {
		t.Fatalf("failed to read output binary: %v", err)
	}
	if string(data) != string(binaryContent) {
		t.Errorf("binary content mismatch: got %d bytes, want %d", len(data), len(binaryContent))
	}

	os.Remove(result.BinaryPath)
}

func TestRemoteBuilder_ServerError(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert, caCertPEM := genCA(t)
	serverKey, serverCert := genCert(t, caCert, caKey, true)
	clientKey, clientCert := genCert(t, caCert, caKey, false)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "build failed: container exited 1"})
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	writeFile(t, filepath.Join(dir, "ca.crt"), caCertPEM)
	writeKeyFile(t, filepath.Join(dir, "client.crt"), clientCert)
	writeECKeyFile(t, filepath.Join(dir, "client.key"), clientKey)

	cfg := &RemoteConfig{
		Address:    server.URL,
		CACert:     filepath.Join(dir, "ca.crt"),
		ClientCert: filepath.Join(dir, "client.crt"),
		ClientKey:  filepath.Join(dir, "client.key"),
		Timeout:    "10s",
	}

	rb, err := NewRemoteBuilder(cfg)
	if err != nil {
		t.Fatalf("NewRemoteBuilder failed: %v", err)
	}

	_, err = rb.Build(context.Background(), &BuildRequest{
		EnvVars:    []string{"OS=linux"},
		BinaryName: "fail_payload",
	})
	if err == nil {
		t.Error("expected error from server 500, got nil")
	}
}

func TestRemoteBuilder_NoClientCert(t *testing.T) {
	dir := t.TempDir()

	caKey, caCert, _ := genCA(t)
	serverKey, serverCert := genCert(t, caCert, caKey, true)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{serverCert.Raw},
			PrivateKey:  serverKey,
		}},
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be reached without client cert")
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, serverTLS)
	srv := &http.Server{Handler: handler}
	go srv.Serve(tlsListener)
	defer srv.Close()

	addr := fmt.Sprintf("https://%s", listener.Addr().String())

	// Create an HTTP client with no client cert
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS13,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	_, err = client.Get(addr + "/health")
	if err == nil {
		t.Error("expected TLS error without client cert, got nil")
	}

	_ = dir
}

// --- test cert helpers ---

func genCA(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	pem := certToPEM(certDER)
	return key, cert, pem
}

func genCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isServer bool) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	usage := x509.ExtKeyUsageClientAuth
	cn := "test-client"
	if isServer {
		usage = x509.ExtKeyUsageServerAuth
		cn = "test-server"
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return key, cert
}

func certToPEM(der []byte) []byte {
	return pemEncode("CERTIFICATE", der)
}

func ecKeyToPEM(key *ecdsa.PrivateKey) []byte {
	b, _ := x509.MarshalECPrivateKey(key)
	return pemEncode("EC PRIVATE KEY", b)
}

func pemEncode(blockType string, data []byte) []byte {
	var buf []byte
	block := &pem.Block{Type: blockType, Bytes: data}
	buf = pem.EncodeToMemory(block)
	return buf
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeKeyFile(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	writeFile(t, path, certToPEM(cert.Raw))
}

func writeECKeyFile(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	writeFile(t, path, ecKeyToPEM(key))
}
