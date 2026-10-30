package main

import (
	"c2/internal/builder"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

type buildRequest struct {
	EnvVars    []string `json:"env_vars"`
	BinaryName string   `json:"binary_name"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	listenAddr := flag.String("listen", ":9443", "address to listen on")
	caCertPath := flag.String("ca-cert", "/app/certs/ca.crt", "CA certificate for client verification")
	serverCertPath := flag.String("server-cert", "/app/certs/server.crt", "server TLS certificate")
	serverKeyPath := flag.String("server-key", "/app/certs/server.key", "server TLS private key")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting NexusC2 Remote Builder Service")

	localBuilder, err := builder.NewLocalBuilder()
	if err != nil {
		log.Fatalf("Failed to initialize local builder: %v", err)
	}

	caCertPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		log.Fatalf("Failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/build", handleBuild(localBuilder))
	mux.HandleFunc("/health", handleHealth)

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("Listening on %s (mTLS required)", *listenAddr)
		if err := server.ListenAndServeTLS(*serverCertPath, *serverKeyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	<-shutdown
	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
		server.Close()
	}
	log.Println("Shutdown complete")
}

func handleBuild(b *builder.LocalBuilder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		clientCN := "unknown"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		var req buildRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
			return
		}

		if req.BinaryName == "" {
			writeError(w, http.StatusBadRequest, "binary_name is required")
			return
		}

		log.Printf("[Build] client=%s binary=%s envs=%d", clientCN, req.BinaryName, len(req.EnvVars))

		result, err := b.Build(r.Context(), &builder.BuildRequest{
			EnvVars:    req.EnvVars,
			BinaryName: req.BinaryName,
		})
		if err != nil {
			log.Printf("[Build] FAILED client=%s binary=%s err=%v", clientCN, req.BinaryName, err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("build failed: %v", err))
			return
		}

		f, err := os.Open(result.BinaryPath)
		if err != nil {
			log.Printf("[Build] Failed to open output binary: %v", err)
			writeError(w, http.StatusInternalServerError, "failed to read built binary")
			return
		}
		defer f.Close()

		stat, err := f.Stat()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to stat built binary")
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
		w.WriteHeader(http.StatusOK)

		written, err := io.Copy(w, f)
		if err != nil {
			log.Printf("[Build] Failed to stream binary to client: %v", err)
			return
		}

		log.Printf("[Build] SUCCESS client=%s binary=%s size=%d", clientCN, req.BinaryName, written)

		os.Remove(result.BinaryPath)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	health := map[string]interface{}{
		"status":     "healthy",
		"goroutines": runtime.NumGoroutine(),
		"memory_mb":  m.HeapAlloc / 1024 / 1024,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
