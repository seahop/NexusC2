// server/docker/payloads/Linux/action_pwd.go

//go:build darwin
// +build darwin

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
