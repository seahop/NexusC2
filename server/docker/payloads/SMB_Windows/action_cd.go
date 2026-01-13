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
			Output:      ctx.WorkingDir,
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
			Output:      ErrCtx(E4, newDir),
			Error:       err,
			ErrorString: Err(E4),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if !info.IsDir() {
		return CommandResult{
			Output:      ErrCtx(E7, newDir),
			Error:       fmt.Errorf(Err(E7)),
			ErrorString: Err(E7),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Update the working directory
	ctx.WorkingDir = newDir

	// For output, convert back to forward slashes for consistency
	displayPath := filepath.ToSlash(newDir)

	return CommandResult{
		Output:      displayPath,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
