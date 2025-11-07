// server/docker/payloads/Windows/action_cd.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"path/filepath"
	"time"
)

type CdCommand struct{}

func (c *CdCommand) Name() string {
	return "cd"
}

// Modified Execute function from action_cd.go
func (c *CdCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// If no args, stay in current directory
	if len(args) == 0 {
		return CommandResult{
			Output:      fmt.Sprintf("Current directory: %s", ctx.WorkingDir),
			ExitCode:    0,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Normalize path separators for the current OS
	targetPath := filepath.FromSlash(args[0])

	var newDir string
	// Handle absolute paths
	if filepath.IsAbs(targetPath) {
		newDir = targetPath
	} else {
		// Handle relative paths
		newDir = filepath.Join(ctx.WorkingDir, targetPath)
	}

	// Clean the path to handle . and .. properly
	newDir = filepath.Clean(newDir)

	// Verify the directory exists and is accessible
	// MODIFIED: Use NetworkAwareStatFile instead of os.Stat
	info, err := NetworkAwareStatFile(newDir)
	if err != nil {
		return CommandResult{
			Output:      fmt.Sprintf("Cannot change directory: %v", err),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if !info.IsDir() {
		err := fmt.Errorf("not a directory: %s", newDir)
		return CommandResult{
			Output:      err.Error(),
			Error:       err,
			ErrorString: err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update the working directory
	ctx.WorkingDir = newDir

	// For output, convert back to forward slashes for consistency
	displayPath := filepath.ToSlash(newDir)

	return CommandResult{
		Output:      fmt.Sprintf("Changed directory to: %s", displayPath),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
