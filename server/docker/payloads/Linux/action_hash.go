// server/docker/payloads/Linux/action_hash.go

//go:build linux
// +build linux

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HashCommand implements the CommandInterface for file hashing
type HashCommand struct{}

func (h *HashCommand) Name() string {
	return "hash"
}

func (h *HashCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse arguments
	targetPath := args[0]
	algorithm := "sha256" // default
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
			return CommandResult{
				Output:      ErrCtx(E4, targetPath),
				Error:       err,
				ErrorString: Err(E4),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return CommandResult{
			Output:      ErrCtx(E10, targetPath),
			Error:       err,
			ErrorString: Err(E10),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Check if it's a directory
	if fileInfo.IsDir() {
		return CommandResult{
			Output:      ErrCtx(E6, targetPath),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Calculate hashes based on algorithm
	switch algorithm {
	case "md5":
		hash, err := calculateMD5(targetPath)
		if err != nil {
			return CommandResult{
				Output:      ErrCtx(E10, targetPath),
				Error:       err,
				ErrorString: Err(E10),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return CommandResult{
			Output:      fmt.Sprintf("MD5:%s:%s", filepath.Base(targetPath), hash),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "sha256":
		hash, err := calculateSHA256(targetPath)
		if err != nil {
			return CommandResult{
				Output:      ErrCtx(E10, targetPath),
				Error:       err,
				ErrorString: Err(E10),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return CommandResult{
			Output:      fmt.Sprintf("SHA256:%s:%s", filepath.Base(targetPath), hash),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	case "all", "both":
		md5Hash, md5Err := calculateMD5(targetPath)
		sha256Hash, sha256Err := calculateSHA256(targetPath)

		var output strings.Builder
		output.WriteString(fmt.Sprintf("%s|%d\n", targetPath, fileInfo.Size()))

		if md5Err != nil {
			output.WriteString(fmt.Sprintf("MD5:%s\n", Err(E10)))
		} else {
			output.WriteString(fmt.Sprintf("MD5:%s\n", md5Hash))
		}

		if sha256Err != nil {
			output.WriteString(fmt.Sprintf("SHA256:%s\n", Err(E10)))
		} else {
			output.WriteString(fmt.Sprintf("SHA256:%s\n", sha256Hash))
		}

		// Determine exit code based on errors
		exitCode := 0
		if md5Err != nil || sha256Err != nil {
			exitCode = 1
		}

		return CommandResult{
			Output:      output.String(),
			ExitCode:    exitCode,
			CompletedAt: time.Now().Format(time.RFC3339),
		}

	default:
		return CommandResult{
			Output:      ErrCtx(E21, algorithm),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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

// HashDirCommand implements CommandInterface for directory hashing
type HashDirCommand struct{}

func (h *HashDirCommand) Name() string {
	return "hashdir"
}

func (h *HashDirCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	targetDir := args[0]
	algorithm := "sha256"
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

	output.WriteString(fmt.Sprintf("%s|%s|%s\n", targetDir, pattern, strings.ToUpper(algorithm)))

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
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
		case "md5":
			hash, hashErr = calculateMD5(path)
		case "sha256":
			hash, hashErr = calculateSHA256(path)
		default:
			hash = Err(E2)
			hashErr = fmt.Errorf(Err(E2))
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
		return CommandResult{
			Output:      output.String(),
			Error:       err,
			ErrorString: Err(E10),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	output.WriteString(fmt.Sprintf("S5:%d|%d\n", fileCount, errorCount))

	exitCode := 0
	if errorCount > 0 {
		exitCode = 1
	}

	return CommandResult{
		Output:      output.String(),
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
