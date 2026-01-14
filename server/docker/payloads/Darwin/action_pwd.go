// server/docker/payloads/Darwin/action_pwd.go

//go:build darwin
// +build darwin

package main

type PwdCommand struct{}

func (c *PwdCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return CommandResult{
		Output:   ctx.WorkingDir,
		ExitCode: 0,
	}
}
