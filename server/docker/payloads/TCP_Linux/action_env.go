// server/docker/payloads/Linux/action_env.go

//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type EnvMsg struct{}

func (c *EnvMsg) execute(ctx *OpCtx, args []string) OpResult {
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
	if args[0] == "-u" {
		if len(args) < 2 {
			return OpResult{
				EStr: Err(E1),
				Output:      Err(E1),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
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
		return OpResult{
			EStr: Err(E2),
			Output:      Err(E2),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Otherwise, get the value of a specific variable
	return c.getEnvVar(arg)
}

func (c *EnvMsg) listAllEnvVars() OpResult {
	envVars := os.Environ()

	// Sort for consistent output
	sort.Strings(envVars)

	output := strings.Join(envVars, "\n")

	return OpResult{
		Output:      output,
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvMsg) getEnvVar(name string) OpResult {
	value := os.Getenv(name)

	if value == "" {
		// Variable doesn't exist or is empty
		return OpResult{
			Output:      ErrCtx(E4, name),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	return OpResult{
		Output:      fmt.Sprintf("%s=%s", name, value),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvMsg) setEnvVar(ctx *OpCtx, name, value string) OpResult {
	// Validate variable name
	if name == "" {
		return OpResult{
			EStr: Err(E2),
			Output:      Err(E2),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Set the environment variable in the OS environment
	err := os.Setenv(name, value)
	if err != nil {
		return OpResult{
			Error:       err,
			EStr: Err(E11),
			Output:      ErrCtx(E11, name),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Also store it in the session context for persistence
	ctx.mu.Lock()
	if ctx.SessionEnv == nil {
		ctx.SessionEnv = make(map[string]string)
	}
	ctx.SessionEnv[name] = value
	ctx.mu.Unlock()

	return OpResult{
		Output:      SuccCtx(S1, name),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

func (c *EnvMsg) unsetEnvVar(ctx *OpCtx, name string) OpResult {
	// Validate variable name
	if name == "" {
		return OpResult{
			EStr: Err(E2),
			Output:      Err(E2),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Check if variable exists
	if _, exists := os.LookupEnv(name); !exists {
		// Check if it's in session env
		ctx.mu.RLock()
		_, inSession := ctx.SessionEnv[name]
		ctx.mu.RUnlock()

		if !inSession {
			return OpResult{
				Output:      ErrCtx(E4, name),
				EC:    1,
				Done: time.Now().Format(time.RFC3339),
			}
		}
	}

	// Unset the environment variable from OS
	err := os.Unsetenv(name)
	if err != nil {
		return OpResult{
			Error:       err,
			EStr: Err(E11),
			Output:      ErrCtx(E11, name),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Remove from session context
	ctx.mu.Lock()
	if ctx.SessionEnv != nil {
		delete(ctx.SessionEnv, name)
	}
	ctx.mu.Unlock()

	return OpResult{
		Output:      SuccCtx(S2, name),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}
