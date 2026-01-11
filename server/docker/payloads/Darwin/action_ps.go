// server/docker/payloads/Darwin/action_ps.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
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
	if runtime.GOOS == "linux" {
		// On Linux, read directly from /proc/[pid]/cmdline
		cmdlineFile := fmt.Sprintf("/proc/%d/cmdline", pid)
		data, err := os.ReadFile(cmdlineFile)
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
	if runtime.GOOS == "linux" {
		// On Linux, use readlink on /proc/[pid]/exe
		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		if path, err := os.Readlink(exeLink); err == nil {
			return path
		}
	}
	return ""
}

// PSCommand implements the command interface for process listing
type PSCommand struct{}

// Name returns the command name
func (c *PSCommand) Name() string {
	return "ps"
}

// Execute runs the ps command with the given arguments
func (c *PSCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	flags := parsePSFlags(args)

	var output strings.Builder

	// Get all processes
	procs, err := process.Processes()
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("[-] Error getting process list: %v", err),
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
			if runtime.GOOS == "linux" {
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
			if runtime.GOOS != "windows" {
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
				Output:   fmt.Sprintf("[-] Error encoding JSON: %v", err),
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
		case "-v", "--verbose":
			flags.Verbose = true
		case "-x", "--extended":
			flags.Extended = true
		case "-j", "--json":
			flags.Json = true
		case "--no-truncate":
			flags.NoTruncate = true
		case "-f", "--filter":
			if i+1 < len(args) {
				flags.Filter = args[i+1]
				i++
			}
		case "-u", "--user":
			if i+1 < len(args) {
				flags.User = args[i+1]
				i++
			}
		case "-s", "--sort":
			if i+1 < len(args) {
				flags.Sort = args[i+1]
				i++
			}
		}
	}

	return flags
}

// parseStatus converts status codes to readable format
func parseStatus(status []string) string {
	if len(status) == 0 {
		return "?"
	}

	// Map common status codes
	statusMap := map[string]string{
		"R": "Running",
		"S": "Sleeping",
		"D": "Disk sleep",
		"T": "Stopped",
		"Z": "Zombie",
		"I": "Idle",
		"W": "Paging",
		"X": "Dead",
	}

	if mapped, ok := statusMap[status[0]]; ok {
		return mapped
	}

	return status[0]
}

// sortProcesses sorts the process list based on the sort field
func sortProcesses(processes []ProcessInfo, sortField string) {
	switch strings.ToLower(sortField) {
	case "cpu":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPU > processes[j].CPU
		})
	case "mem", "memory":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].Memory > processes[j].Memory
		})
	case "name":
		sort.Slice(processes, func(i, j int) bool {
			return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
		})
	case "user":
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
func formatProcessTable(output *strings.Builder, processes []ProcessInfo, flags PSFlags) {
	// Build header based on flags
	header := "PID\tPPID\tNAME"

	if flags.Extended {
		header += "\tUSER\tCPU%\tMEM%\tMEM(MB)\tSTATUS"
	}

	if flags.Verbose {
		header += "\tCOMMAND"
	}

	output.WriteString(header + "\n")
	output.WriteString(strings.Repeat("-", 80) + "\n")

	// Format each process
	for _, p := range processes {
		line := fmt.Sprintf("%d\t%d\t%s", p.PID, p.PPID, truncatePS(p.Name, 15, flags.NoTruncate))

		if flags.Extended {
			user := truncatePS(p.Username, 12, flags.NoTruncate)
			if user == "" {
				user = "?"
			}
			line += fmt.Sprintf("\t%s\t%.1f\t%.1f\t%.1f\t%s",
				user, p.CPU, p.Memory, p.MemoryMB, truncatePS(p.Status, 8, flags.NoTruncate))
		}

		if flags.Verbose {
			cmd := p.CommandLine
			if cmd == "" {
				cmd = p.Executable
			}
			if cmd == "" {
				cmd = "?"
			}
			line += "\t" + truncatePS(cmd, 50, flags.NoTruncate)
		}

		output.WriteString(line + "\n")
	}

	output.WriteString(fmt.Sprintf("\nTotal processes: %d\n", len(processes)))
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
