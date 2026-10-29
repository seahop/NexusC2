// server/docker/payloads/Windows/action_bof_async.go
//go:build windows
// +build windows

package main

import (
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"time"
)

// BOF async command strings are defined via template in action_bof.go
// Use bofTpl() and convenience functions to access them

// AsyncTaskMsg handles async BOF execution
type AsyncTaskMsg struct {
	tpl *TaskCfg
}

func (c *AsyncTaskMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data if available
	if ctx.CurrentMsg != nil && ctx.CurrentMsg.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
		if err == nil {
			c.tpl = &TaskCfg{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if runtime.GOOS != osWindows {
		return OpResult{
			Output:      Err(E25),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}
	// Will be handled by processBOFAsync with full command data
	return OpResult{
		Output:      Succ(S4),
		EC:    0,
		Done: time.Now().Format(time.RFC3339),
	}
}

// JobListMsg lists async BOF jobs
type JobListMsg struct {
	tpl *TaskCfg
}

func (c *JobListMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data if available
	if ctx.CurrentMsg != nil && ctx.CurrentMsg.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
		if err == nil {
			c.tpl = &TaskCfg{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if runtime.GOOS != osWindows {
		return OpResult{
			Output:      Err(E25),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Call platform-specific implementation
	return executeBOFJobsList()
}

// TaskOutputMsg retrieves output from an async BOF job
type TaskOutputMsg struct {
	tpl *TaskCfg
}

func (c *TaskOutputMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data if available
	if ctx.CurrentMsg != nil && ctx.CurrentMsg.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
		if err == nil {
			c.tpl = &TaskCfg{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if runtime.GOOS != osWindows {
		return OpResult{
			Output:      Err(E25),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	jobID := args[0]
	return executeBOFGetOutput(jobID)
}

// JobStopMsg terminates an async BOF job
type JobStopMsg struct {
	tpl *TaskCfg
}

func (c *JobStopMsg) execute(ctx *OpCtx, args []string) OpResult {
	// Parse template from Msg.Data if available
	if ctx.CurrentMsg != nil && ctx.CurrentMsg.Data != "" {
		decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentMsg.Data)
		if err == nil {
			c.tpl = &TaskCfg{}
			if err := json.Unmarshal(decoded, c.tpl); err == nil {
				SetBOFTemplate(c.tpl.Templates)
			}
		}
	}

	osWindows := bofOSWindows()
	if runtime.GOOS != osWindows {
		return OpResult{
			Output:      Err(E25),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return OpResult{
			Output:      Err(E1),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	jobID := args[0]
	return executeBOFKillJob(jobID)
}

// processBOFAsync handles async BOF execution (called from WorkQueue)
func (cq *WorkQueue) processBOFAsync(cmd Msg) OpResult {
	osWindows := bofOSWindows()
	if runtime.GOOS != osWindows {
		return OpResult{
			Cmd:     cmd,
			Output:      Err(E25),
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	// Decode BOF and parse arguments (reuse existing logic)
	bofBytes, err := base64.StdEncoding.DecodeString(cmd.Data)
	if err != nil {
		return OpResult{
			Cmd:     cmd,
			Output:      Err(E18),
			Error:       err,
			EC:    1,
			Done: time.Now().Format(time.RFC3339),
		}
	}

	var bofArgs []byte
	asyncPrefix := bofAsyncCmdPrefix()
	if cmd.Cmd != "" && strings.HasPrefix(cmd.Cmd, asyncPrefix) {
		argString := strings.TrimPrefix(cmd.Cmd, asyncPrefix)
		if argString != "" {
			parsedArgs, err := parseBOFArguments(argString)
			if err != nil {
			} else {
				bofArgs = parsedArgs
			}
		}
	}

	// execute async on Windows (platform-specific)
	return executeBOFAsyncPlatform(cmd, bofBytes, bofArgs)
}
