// server/docker/payloads/Darwin/action_env.go

//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type EnvCommand struct{}

func (c *EnvCommand) Name() string {
	return "env"
}

func (c *EnvCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Apply any session environment variables first
	ctx.mu.RLock()
	for key, value := range ctx.SessionEnv {
		os.Setenv(key, value)
	}
	ctx.mu.RUnlock()

	// No arguments - display all environment variables
	if len(args) == 0 {
		return c.listAllEnvVars()
	}

	// Check for unset flags
	if args[0] == "-u" || args[0] == "--unset" {
		if len(args) < 2 {
			return CommandResult{
				ErrorString: Err(E1),
				Output:      Err(E1),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
		return c.unsetEnvVar(ctx, args[1])
	}

	// Single argument - check if it's setting or getting
	arg := args[0]

	// Check if it contains '=' for setting a variable
	if strings.Contains(arg, "=") {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) == 2 {
			return c.setEnvVar(ctx, parts[0], parts[1])
		}
		return CommandResult{
			ErrorString: Err(E2),
			Output:      Err(E2),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Otherwise, get the value of a specific variable
	return c.getEnvVar(arg)
}

func (c *EnvCommand) listAllEnvVars() CommandResult {
	envVars := os.Environ()

	// Sort for consistent output
	sort.Strings(envVars)

	output := strings.Join(envVars, "\n")

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvCommand) getEnvVar(name string) CommandResult {
	value := os.Getenv(name)

	if value == "" {
		// Variable doesn't exist or is empty
		return CommandResult{
			Output:      ErrCtx(E4, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      fmt.Sprintf("%s=%s", name, value),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvCommand) setEnvVar(ctx *CommandContext, name, value string) CommandResult {
	// Validate variable name
	if name == "" {
		return CommandResult{
			ErrorString: Err(E2),
			Output:      Err(E2),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Set the environment variable in the OS environment
	err := os.Setenv(name, value)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E11),
			Output:      ErrCtx(E11, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Also store it in the session context for persistence
	ctx.mu.Lock()
	if ctx.SessionEnv == nil {
		ctx.SessionEnv = make(map[string]string)
	}
	ctx.SessionEnv[name] = value
	ctx.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S1, name),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvCommand) unsetEnvVar(ctx *CommandContext, name string) CommandResult {
	// Validate variable name
	if name == "" {
		return CommandResult{
			ErrorString: Err(E2),
			Output:      Err(E2),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Check if variable exists
	if _, exists := os.LookupEnv(name); !exists {
		// Check if it's in session env
		ctx.mu.RLock()
		_, inSession := ctx.SessionEnv[name]
		ctx.mu.RUnlock()

		if !inSession {
			return CommandResult{
				Output:      ErrCtx(E4, name),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Unset the environment variable from OS
	err := os.Unsetenv(name)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E11),
			Output:      ErrCtx(E11, name),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Remove from session context
	ctx.mu.Lock()
	if ctx.SessionEnv != nil {
		delete(ctx.SessionEnv, name)
	}
	ctx.mu.Unlock()

	return CommandResult{
		Output:      SuccCtx(S2, name),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
