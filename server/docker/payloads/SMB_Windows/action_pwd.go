// server/docker/payloads/Windows/action_pwd.go
//go:build windows
// +build windows

package main

import "fmt"

type PwdCommand struct{}

func (c *PwdCommand) Name() string {
	return "pwd"
}

func (c *PwdCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return CommandResult{
		Output:   fmt.Sprintf("Current working directory:\n%s", ctx.WorkingDir),
		ExitCode: 0,
	}
}
