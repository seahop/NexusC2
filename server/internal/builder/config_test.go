package builder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"", 10 * time.Minute},
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"1h", time.Hour},
		{"invalid", 10 * time.Minute},
	}

	for _, tt := range tests {
		rc := &RemoteConfig{Timeout: tt.input}
		got := rc.ParseTimeout()
		if got != tt.expected {
			t.Errorf("ParseTimeout(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestNewBuilderFromConfig_Local(t *testing.T) {
	cfg := &BuilderConfig{Mode: "local"}
	b, err := NewBuilderFromConfig(cfg)
	if err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	if _, ok := b.(*LocalBuilder); !ok {
		t.Errorf("expected *LocalBuilder, got %T", b)
	}
}

func TestNewBuilderFromConfig_EmptyDefaultsToLocal(t *testing.T) {
	cfg := &BuilderConfig{Mode: ""}
	b, err := NewBuilderFromConfig(cfg)
	if err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	if _, ok := b.(*LocalBuilder); !ok {
		t.Errorf("expected *LocalBuilder, got %T", b)
	}
}

func TestNewBuilderFromConfig_UnknownMode(t *testing.T) {
	cfg := &BuilderConfig{Mode: "cloud"}
	_, err := NewBuilderFromConfig(cfg)
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
}

func TestNewBuilderFromConfig_Remote(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", ca, caKey, false)

	cfg := &BuilderConfig{
		Mode: "remote",
		Remote: RemoteConfig{
			Address:    "https://localhost:9999",
			CACert:     filepath.Join(dir, "ca.crt"),
			ClientCert: filepath.Join(dir, "client.crt"),
			ClientKey:  filepath.Join(dir, "client.key"),
			Timeout:    "5m",
		},
	}
	b, err := NewBuilderFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewBuilderFromConfig failed: %v", err)
	}
	if _, ok := b.(*RemoteBuilder); !ok {
		t.Errorf("expected *RemoteBuilder, got %T", b)
	}
}

func TestTLSConfig(t *testing.T) {
	dir := t.TempDir()
	ca, caKey := generateTestCA(t, dir)
	generateTestCert(t, dir, "client", ca, caKey, false)

	rc := &RemoteConfig{
		CACert:     filepath.Join(dir, "ca.crt"),
		ClientCert: filepath.Join(dir, "client.crt"),
		ClientKey:  filepath.Join(dir, "client.key"),
	}

	tlsCfg, err := rc.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig failed: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 minimum, got %d", tlsCfg.MinVersion)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("expected non-nil RootCAs")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("expected 1 client cert, got %d", len(tlsCfg.Certificates))
	}
}

func TestTLSConfig_MissingFiles(t *testing.T) {
	rc := &RemoteConfig{
		CACert:     "/nonexistent/ca.crt",
		ClientCert: "/nonexistent/client.crt",
		ClientKey:  "/nonexistent/client.key",
	}
	_, err := rc.TLSConfig()
	if err == nil {
		t.Error("expected error for missing cert files, got nil")
	}
}

// --- test helpers ---

func generateTestCA(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey) {
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

	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", certDER)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	writePEM(t, filepath.Join(dir, "ca.key"), "EC PRIVATE KEY", keyDER)

	return cert, key
}

func generateTestCert(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, isServer bool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	usage := x509.ExtKeyUsageClientAuth
	if isServer {
		usage = x509.ExtKeyUsageServerAuth
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", certDER)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	writePEM(t, filepath.Join(dir, name+".key"), "EC PRIVATE KEY", keyDER)
}

func writePEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		t.Fatal(err)
	}
}
