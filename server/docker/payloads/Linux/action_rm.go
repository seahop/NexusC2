// server/docker/payloads/Linux/action_rm.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RmCommand handles file and directory removal
type RmCommand struct{}

func (c *RmCommand) Name() string {
	return "rm"
}

func (c *RmCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Check if no arguments provided
	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse flags
	recursive := false
	force := false
	var targets []string

	for _, arg := range args {
		// Check for combined flags like -rf or -fr
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			flagStr := strings.TrimPrefix(arg, "-")
			if strings.Contains(flagStr, "r") || strings.Contains(flagStr, "R") {
				recursive = true
			}
			if strings.Contains(flagStr, "f") {
				force = true
			}
			// Check for individual flags
			if flagStr == "r" || flagStr == "R" {
				recursive = true
			} else if flagStr == "f" {
				force = true
			}
		} else if arg == "--recursive" {
			recursive = true
		} else if arg == "--force" {
			force = true
		} else {
			// It's a target file/directory
			targets = append(targets, arg)
		}
	}

	// Check if we have any targets to remove
	if len(targets) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Get current working directory from context
	ctx.mu.RLock()
	workingDir := ctx.WorkingDir
	ctx.mu.RUnlock()

	var errors []string
	hasErrors := false
	successCount := 0

	// Process each target
	for _, target := range targets {
		var targetPath string

		if filepath.IsAbs(target) || strings.HasPrefix(target, "\\\\") || strings.HasPrefix(target, "//") {
			targetPath = target
		} else {
			// Handle UNC paths in working directory
			if strings.HasPrefix(workingDir, "\\\\") || strings.HasPrefix(workingDir, "//") {
				workingDirNorm := strings.ReplaceAll(workingDir, "/", "\\")
				if !strings.HasSuffix(workingDirNorm, "\\") {
					workingDirNorm += "\\"
				}
				targetPath = workingDirNorm + target
			} else {
				targetPath = filepath.Join(workingDir, target)
			}
		}

		// Clean path while preserving UNC
		if strings.HasPrefix(targetPath, "\\\\") || strings.HasPrefix(targetPath, "//") {
			targetPath = strings.ReplaceAll(targetPath, "/", "\\")
			parts := strings.Split(targetPath, "\\")
			var cleanParts []string
			for _, part := range parts {
				if part != "" && part != "." {
					cleanParts = append(cleanParts, part)
				}
			}
			if len(cleanParts) >= 2 {
				targetPath = "\\\\" + strings.Join(cleanParts, "\\")
			}
		} else {
			targetPath = filepath.Clean(targetPath)
		}

		// Check if the target exists
		// MODIFIED: Use NetworkAwareStatFile instead of os.Stat
		info, err := NetworkAwareStatFile(targetPath)
		if err != nil {
			if os.IsNotExist(err) {
				if !force {
					// Only report error if not in force mode
					errors = append(errors, ErrCtx(E4, target))
					hasErrors = true
				}
				continue
			} else if os.IsPermission(err) {
				// Permission denied on stat
				errors = append(errors, ErrCtx(E3, target))
				hasErrors = true
				continue
			} else {
				// Other stat errors
				errors = append(errors, ErrCtx(E10, target))
				hasErrors = true
				continue
			}
		}

		// Check if it's a directory
		if info.IsDir() {
			if !recursive {
				errors = append(errors, ErrCtx(E6, target))
				hasErrors = true
				continue
			}

			// Remove directory recursively
			removedCount, err := removeAllWithDetails(targetPath, force)
			if err != nil {
				errors = append(errors, ErrCtx(E11, target))
				hasErrors = true
			} else {
				successCount++
			}
			_ = removedCount
		} else {
			// Remove single file
			// MODIFIED: Use NetworkAwareRemove instead of os.Remove
			err = NetworkAwareRemove(targetPath)
			if err != nil {
				if os.IsPermission(err) {
					errors = append(errors, ErrCtx(E3, target))
					hasErrors = true
				} else if !force {
					errors = append(errors, ErrCtx(E11, target))
					hasErrors = true
				}
			} else {
				successCount++
			}
		}
	}

	// Prepare final output
	var finalOutput string

	if len(errors) > 0 {
		finalOutput = strings.Join(errors, "\n")
	} else if successCount > 0 {
		finalOutput = SuccCtx(S2, fmt.Sprintf("%d", successCount))
	} else {
		finalOutput = Succ(S0)
	}

	exitCode := 0
	if hasErrors {
		exitCode = 1
	}

	return CommandResult{
		Output:      finalOutput,
		ExitCode:    exitCode,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Modified removeAllWithDetails function from action_rm.go
func removeAllWithDetails(path string, force bool) (int, error) {
	removedCount := 0

	// First, check if we can access the directory
	// MODIFIED: Use NetworkAwareOpenFile to open directory
	dir, err := NetworkAwareOpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsPermission(err) {
			return 0, fmt.Errorf(Err(E3))
		}
		return 0, fmt.Errorf(Err(E10))
	}

	// Read all directory entries
	entries, err := dir.Readdir(-1)
	dir.Close() // Close immediately after reading

	if err != nil {
		if os.IsPermission(err) {
			return 0, fmt.Errorf(Err(E3))
		}
		return 0, fmt.Errorf(Err(E10))
	}

	// Track errors during recursive deletion
	var lastError error

	// Remove all entries
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())

		if entry.IsDir() {
			// Recursively remove subdirectory
			subCount, err := removeAllWithDetails(entryPath, force)
			removedCount += subCount

			if err != nil {
				lastError = err
				if !force {
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf(Err(E11))
				}
				// In force mode, continue trying other items
			} else {
				removedCount++ // Count the subdirectory itself
			}
		} else {
			// Remove file
			// MODIFIED: Use NetworkAwareRemove instead of os.Remove
			err := NetworkAwareRemove(entryPath)
			if err != nil {
				if os.IsPermission(err) {
					lastError = fmt.Errorf(Err(E3))
				} else {
					lastError = fmt.Errorf(Err(E11))
				}

				if !force {
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf(Err(E11))
				}
				// In force mode, continue trying other items
			} else {
				removedCount++
			}
		}
	}

	// Now try to remove the empty directory
	// MODIFIED: Use NetworkAwareRemove instead of os.Remove
	err = NetworkAwareRemove(path)
	if err != nil {
		if os.IsPermission(err) {
			return removedCount, fmt.Errorf(Err(E3))
		}
		return removedCount, fmt.Errorf(Err(E11))
	}

	// If there was an error during processing but we still removed the directory,
	// report the success with a note about the error
	if lastError != nil && force {
		return removedCount, nil // In force mode, we consider it success if the directory is gone
	}

	return removedCount, nil
}

// parseRemovalError creates error code messages
func parseRemovalError(target string, err error) string {
	errStr := err.Error()

	// Check for common error patterns
	if strings.Contains(errStr, "permission denied") || os.IsPermission(err) {
		return ErrCtx(E3, target)
	}

	if strings.Contains(errStr, "directory not empty") {
		return ErrCtx(E16, target)
	}

	if strings.Contains(errStr, "resource busy") || strings.Contains(errStr, "device or resource busy") {
		return ErrCtx(E13, target)
	}

	if strings.Contains(errStr, "read-only file system") {
		return ErrCtx(E14, target)
	}

	if strings.Contains(errStr, "operation not permitted") {
		return ErrCtx(E15, target)
	}

	// Default
	return ErrCtx(E11, target)
}
