// server/docker/payloads/Linux/action_pwd.go

//go:build linux
// +build linux

package main

type GetDirMsg struct{}

func (c *GetDirMsg) execute(ctx *OpCtx, args []string) OpResult {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return OpResult{
		Output:   ctx.WorkingDir,
		EC: 0,
	}
}
