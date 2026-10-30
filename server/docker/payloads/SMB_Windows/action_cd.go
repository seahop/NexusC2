// server/docker/payloads/Windows/action_cd.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"path/filepath"
	"time"
)

type ChDirMsg struct{}

// Modified execute function from action_cd.go
func (c *ChDirMsg) execute(ctx *OpCtx, args []string) OpResult {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// If no args, stay in current directory
	if len(args) == 0 {
		return OpResult{
			Output:      ctx.WorkingDir,
			EC:    0,
			Done: time.Now().Format(time.RFC3339),
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
		return OpResult{
			Output:      ErrCtx(E4, newDir),
			Error:       err,
			EStr: Err(E4),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	if !info.IsDir() {
		return OpResult{
			Output:      ErrCtx(E7, newDir),
			Error:       fmt.Errorf("%s", Err(E7)),
			EStr: Err(E7),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Update the working directory
	ctx.WorkingDir = newDir

	// For output, convert back to forward slashes for consistency
	displayPath := filepath.ToSlash(newDir)

	return OpResult{
		Output:      displayPath,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
