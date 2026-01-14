// server/docker/payloads/SMB_Windows/action_pwd.go
//go:build windows
// +build windows

package main

type PwdCommand struct{}

func (c *PwdCommand) Name() string {
	return "pwd"
}

func (c *PwdCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return CommandResult{
		Output:   ctx.WorkingDir,
		ExitCode: 0,
	}
}