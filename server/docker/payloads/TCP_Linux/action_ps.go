// server/docker/payloads/Linux/action_ps.go

//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// PS strings (constructed to avoid static signatures)
var (
	// Flag arguments - short
	psFlagV = string([]byte{0x2d, 0x76})       // -v
	psFlagX = string([]byte{0x2d, 0x78})       // -x
	psFlagJ = string([]byte{0x2d, 0x6a})       // -j
	psFlagF = string([]byte{0x2d, 0x66})       // -f
	psFlagU = string([]byte{0x2d, 0x75})       // -u
	psFlagS = string([]byte{0x2d, 0x73})       // -s

	// Flag arguments - long
	psVerbose    = string([]byte{0x2d, 0x2d, 0x76, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x65})                                     // --verbose
	psExtended   = string([]byte{0x2d, 0x2d, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64})                               // --extended
	psJson       = string([]byte{0x2d, 0x2d, 0x6a, 0x73, 0x6f, 0x6e})                                                       // --json
	psNoTruncate = string([]byte{0x2d, 0x2d, 0x6e, 0x6f, 0x2d, 0x74, 0x72, 0x75, 0x6e, 0x63, 0x61, 0x74, 0x65})             // --no-truncate
	psFilter     = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72})                                           // --filter
	psUser       = string([]byte{0x2d, 0x2d, 0x75, 0x73, 0x65, 0x72})                                                       // --user
	psSort       = string([]byte{0x2d, 0x2d, 0x73, 0x6f, 0x72, 0x74})                                                       // --sort

	// Sort field values
	psSortCPU    = string([]byte{0x63, 0x70, 0x75})                               // cpu
	psSortMem    = string([]byte{0x6d, 0x65, 0x6d})                               // mem
	psSortMemory = string([]byte{0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79})             // memory
	psSortName   = string([]byte{0x6e, 0x61, 0x6d, 0x65})                         // name
	psSortUser   = string([]byte{0x75, 0x73, 0x65, 0x72})                         // user

	// OS names
	psOSLinux   = string([]byte{0x6c, 0x69, 0x6e, 0x75, 0x78})                   // linux
	psOSWindows = string([]byte{0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73})       // windows

	// Proc paths
	psProcCmdline = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x25, 0x64, 0x2f, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65}) // /proc/%d/cmdline
	psProcExe     = string([]byte{0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x25, 0x64, 0x2f, 0x65, 0x78, 0x65})                         // /proc/%d/exe

	// Command name
	psCmdName = string([]byte{0x70, 0x73}) // ps
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
	Verbose    bool   // -v or --verbose: include command line, executable path
	Extended   bool   // -x or --extended: include CPU, memory, threads, etc
	Json       bool   // -j or --json: output in JSON format
	NoTruncate bool   // --no-truncate: don't truncate any fields in output
	Filter     string // -f or --filter: filter by process name
	User       string // -u or --user: filter by username
	Sort       string // -s or --sort: sort by field (cpu, mem, pid, name)
}

// getFullCommandLine attempts to get the full command line without truncation
func getFullCommandLine(pid int32) string {
	if runtime.GOOS == psOSLinux {
		// On Linux, read directly from /proc/[pid]/cmdline
		cmdlineFile := fmt.Sprintf(psProcCmdline, pid)
		data, err := ioutil.ReadFile(cmdlineFile)
		if err == nil && len(data) > 0 {
			// Replace null bytes with spaces and get FULL command line
			cmdline := string(bytes.ReplaceAll(data, []byte{0}, []byte{' '}))
			cmdline = strings.TrimSpace(cmdline)
			return cmdline
		}
	}
	return ""
}

// getFullExecutablePath attempts to get the full executable path without truncation
func getFullExecutablePath(pid int32) string {
	if runtime.GOOS == psOSLinux {
		// On Linux, use readlink on /proc/[pid]/exe
		exeLink := fmt.Sprintf(psProcExe, pid)
		if path, err := os.Readlink(exeLink); err == nil {
			return path
		}
	}
	return ""
}

// PSCommand implements the command interface for process listing
type PSCommand struct{}

// Execute runs the ps command with the given arguments
func (c *PSCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	flags := parsePSFlags(args)

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
			// Always try to get full data when NoTruncate is set
			if runtime.GOOS == psOSLinux {
				// On Linux, read directly from /proc to avoid any truncation
				if fullCmd := getFullCommandLine(p.Pid); fullCmd != "" {
					procInfo.CommandLine = fullCmd
				} else if cmdline, err := p.Cmdline(); err == nil && cmdline != "" {
					procInfo.CommandLine = cmdline
				}

				if fullExe := getFullExecutablePath(p.Pid); fullExe != "" {
					procInfo.Executable = fullExe
				} else if exe, err := p.Exe(); err == nil {
					procInfo.Executable = exe
				}
			} else {
				// For other OS, use gopsutil methods
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

			// CPU percent (this might be 0 on first call)
			if cpu, err := p.CPUPercent(); err == nil {
				procInfo.CPU = cpu
			}

			// Memory info
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

			// File descriptors (Linux/Unix only)
			if runtime.GOOS != psOSWindows {
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
	sortProcesses(processes, flags.Sort)

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
		formatProcessTable(&output, processes, flags)
	}

	return CommandResult{
		Output:   output.String(),
		ExitCode: 0,
	}
}

// parsePSFlags parses command line flags
func parsePSFlags(args []string) PSFlags {
	flags := PSFlags{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case psFlagV, psVerbose:
			flags.Verbose = true
		case psFlagX, psExtended:
			flags.Extended = true
		case psFlagJ, psJson:
			flags.Json = true
		case psNoTruncate:
			flags.NoTruncate = true
		case psFlagF, psFilter:
			if i+1 < len(args) {
				flags.Filter = args[i+1]
				i++
			}
		case psFlagU, psUser:
			if i+1 < len(args) {
				flags.User = args[i+1]
				i++
			}
		case psFlagS, psSort:
			if i+1 < len(args) {
				flags.Sort = args[i+1]
				i++
			}
		}
	}

	return flags
}

// parseStatus converts status codes to short markers (decoded client-side)
func parseStatus(status []string) string {
	if len(status) == 0 {
		return "?"
	}

	// Map to short status codes - client expands these
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
func sortProcesses(processes []ProcessInfo, sortField string) {
	switch strings.ToLower(sortField) {
	case psSortCPU:
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPU > processes[j].CPU
		})
	case psSortMem, psSortMemory:
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].Memory > processes[j].Memory
		})
	case psSortName:
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
		})
	case psSortUser:
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Username) < strings.ToLower(processes[j].Username)
		})
	default: // Default to PID
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].PID < processes[j].PID
		})
	}
}

// formatProcessTable formats the process list as a table with dynamic column widths
func formatProcessTable(output *strings.Builder, processes []ProcessInfo, flags PSFlags) {
	// Calculate column widths based on data
	widths := struct {
		pid, ppid, name, user, cpu, mem, memMB, status, cmd int
	}{
		pid:    3, // "PID"
		ppid:   4, // "PPID"
		name:   4, // "NAME"
		user:   4, // "USER"
		cpu:    4, // "CPU%"
		mem:    4, // "MEM%"
		memMB:  7, // "MEM(MB)"
		status: 6, // "STATUS"
		cmd:    7, // "COMMAND"
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
	_ = fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds", widths.pid, widths.ppid, widths.name) // headerFormat - client adds headers

	extFormat := ""
	if flags.Extended {
		extFormat = fmt.Sprintf("  %%-%ds  %%%ds  %%%ds  %%%ds  %%-%ds",
			widths.user, widths.cpu, widths.mem, widths.memMB, widths.status)
	}

	verboseFormat := ""
	if flags.Verbose {
		verboseFormat = "  %s"
	}

	// Write table marker - client adds header based on type
	// T:F = basic, T:G = extended, T:H = verbose, T:I = full (extended+verbose)
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
// This is a local function to avoid conflicts with other truncateString functions
func truncatePS(s string, maxLen int, noTruncate bool) string {
	if noTruncate || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
