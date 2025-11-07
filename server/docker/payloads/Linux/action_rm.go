// server/docker/payloads/Linux/action_rm.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
			Output: `Usage: rm [options] <file/directory>...
Options:
  -r, -R, --recursive  Remove directories and their contents recursively
  -f, --force         Ignore nonexistent files, never prompt
  -rf, -fr            Combine recursive and force options
  
Examples:
  rm file.txt              # Remove a single file
  rm file1.txt file2.txt   # Remove multiple files
  rm -r directory          # Remove directory and its contents
  rm -rf directory         # Force remove directory without prompts
  rm -f nonexistent.txt    # Don't error if file doesn't exist
  
Note: Directories are always removed recursively when -r is specified.`,
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
			Output:      "rm: missing operand\nTry 'rm --help' for more information.",
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
					// Only report error if not in force mode
					errors = append(errors, fmt.Sprintf("rm: cannot remove '%s': No such file or directory", target))
					hasErrors = true
				} else {
					// In force mode, count as success for non-existent files
					output.WriteString(fmt.Sprintf("Skipped (does not exist): %s\n", target))
				}
				continue
			} else if os.IsPermission(err) {
				// Permission denied on stat
				errors = append(errors, fmt.Sprintf("rm: cannot access '%s': Permission denied", target))
				hasErrors = true
				continue
			} else {
				// Other stat errors
				errors = append(errors, fmt.Sprintf("rm: cannot access '%s': %v", target, err))
				hasErrors = true
				continue
			}
		}

		// Check if it's a directory
		if info.IsDir() {
			if !recursive {
				errors = append(errors, fmt.Sprintf("rm: cannot remove '%s': Is a directory (use -r to remove directories)", target))
				hasErrors = true
				continue
			}

			// Remove directory recursively
			removedCount, err := removeAllWithDetails(targetPath, force)
			if err != nil {
				// Parse the error to provide more helpful messages
				errMsg := parseRemovalError(target, err)
				errors = append(errors, errMsg)
				hasErrors = true
				if removedCount > 0 {
					output.WriteString(fmt.Sprintf("Partially removed directory '%s': %d items deleted before error\n", target, removedCount))
				}
			} else {
				output.WriteString(fmt.Sprintf("Removed directory '%s' and %d items within\n", target, removedCount))
				successCount++
			}
		} else {
			// Remove single file
			// MODIFIED: Use NetworkAwareRemove instead of os.Remove
			err = NetworkAwareRemove(targetPath)
			if err != nil {
				if os.IsPermission(err) {
					errors = append(errors, fmt.Sprintf("rm: cannot remove '%s': Permission denied", target))
					hasErrors = true
				} else if !force {
					errors = append(errors, fmt.Sprintf("rm: cannot remove '%s': %v", target, err))
					hasErrors = true
				}
			} else {
				output.WriteString(fmt.Sprintf("Removed file: %s\n", target))
				successCount++
			}
		}
	}

	// Prepare final output
	finalOutput := output.String()

	// Add summary if multiple targets
	if len(targets) > 1 {
		if successCount > 0 {
			finalOutput += fmt.Sprintf("\nSummary: Successfully removed %d out of %d targets\n", successCount, len(targets))
		}
	}

	if len(errors) > 0 {
		if finalOutput != "" {
			finalOutput += "\nErrors encountered:\n"
		}
		finalOutput += strings.Join(errors, "\n")
	}

	// If no output was generated and no errors, provide a success message
	if finalOutput == "" && !hasErrors {
		if len(targets) == 1 {
			finalOutput = fmt.Sprintf("Successfully removed: %s", targets[0])
		} else {
			finalOutput = fmt.Sprintf("Successfully removed %d items", len(targets))
		}
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
			return 0, fmt.Errorf("permission denied")
		}
		return 0, err
	}

	// Read all directory entries
	entries, err := dir.Readdir(-1)
	dir.Close() // Close immediately after reading

	if err != nil {
		if os.IsPermission(err) {
			return 0, fmt.Errorf("permission denied reading directory contents")
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
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf("failed to remove '%s': %v", entry.Name(), err)
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
					lastError = fmt.Errorf("permission denied on file '%s'", entry.Name())
				} else {
					lastError = err
				}

				if !force {
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf("failed to remove '%s': %v", entry.Name(), err)
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
			return removedCount, fmt.Errorf("permission denied removing directory after clearing contents")
		}
		// If we couldn't remove the directory but removed some contents, report partial success
		if removedCount > 0 {
			return removedCount, fmt.Errorf("removed %d items but couldn't remove directory itself: %v", removedCount, err)
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

// parseRemovalError creates user-friendly error messages
func parseRemovalError(target string, err error) string {
	errStr := err.Error()

	// Check for common error patterns
	if strings.Contains(errStr, "permission denied") || os.IsPermission(err) {
		// Provide OS-specific hints for permission issues
		if runtime.GOOS == "windows" {
			return fmt.Sprintf("rm: cannot remove '%s': Permission denied (file may be in use or require administrator privileges)", target)
		} else {
			return fmt.Sprintf("rm: cannot remove '%s': Permission denied (may require elevated privileges)", target)
		}
	}

	if strings.Contains(errStr, "directory not empty") {
		return fmt.Sprintf("rm: cannot remove '%s': Directory not empty (some files could not be deleted)", target)
	}

	if strings.Contains(errStr, "resource busy") || strings.Contains(errStr, "device or resource busy") {
		return fmt.Sprintf("rm: cannot remove '%s': Resource busy (file or directory is in use)", target)
	}

	if strings.Contains(errStr, "read-only file system") {
		return fmt.Sprintf("rm: cannot remove '%s': Read-only file system", target)
	}

	if strings.Contains(errStr, "operation not permitted") {
		return fmt.Sprintf("rm: cannot remove '%s': Operation not permitted (may be immutable or system file)", target)
	}

	// Default: return the original error with the target
	return fmt.Sprintf("rm: cannot remove '%s': %v", target, err)
}
