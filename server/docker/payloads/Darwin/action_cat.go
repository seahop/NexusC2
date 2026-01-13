// server/docker/payloads/Darwin/action_cat.go
//go:build darwin
// +build darwin

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CatCommand struct{}

type catOptions struct {
	grepPattern     string
	caseInsensitive bool
}

func (c *CatCommand) Name() string {
	return "cat"
}

func (c *CatCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	if len(args) == 0 {
		return CommandResult{
			ErrorString: Err(E1),
			Output:      Err(E1),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Parse arguments
	fileName, opts, err := c.parseArgs(args)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E2),
			Output:      Err(E2),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Resolve file path
	filePath := fileName
	if !filepath.IsAbs(filePath) && !strings.HasPrefix(filePath, "\\\\") && !strings.HasPrefix(filePath, "//") {
		ctx.mu.RLock()
		workingDir := ctx.WorkingDir
		ctx.mu.RUnlock()

		// Handle UNC paths in working directory
		if strings.HasPrefix(workingDir, "\\\\") || strings.HasPrefix(workingDir, "//") {
			workingDir = strings.ReplaceAll(workingDir, "/", "\\")
			if !strings.HasSuffix(workingDir, "\\") {
				workingDir += "\\"
			}
			filePath = workingDir + fileName
		} else {
			filePath = filepath.Join(workingDir, fileName)
		}
	}

	// Clean path while preserving UNC
	if strings.HasPrefix(filePath, "\\\\") || strings.HasPrefix(filePath, "//") {
		filePath = strings.ReplaceAll(filePath, "/", "\\")
		parts := strings.Split(filePath, "\\")
		var cleanParts []string
		for _, part := range parts {
			if part != "" && part != "." {
				cleanParts = append(cleanParts, part)
			}
		}
		if len(cleanParts) >= 2 {
			filePath = "\\\\" + strings.Join(cleanParts, "\\")
		}
	} else {
		filePath = filepath.Clean(filePath)
	}

	// Read and process the file
	output, err := c.readFile(filePath, opts)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: Err(E10),
			Output:      ErrCtx(E10, fileName),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

func (c *CatCommand) parseArgs(args []string) (string, catOptions, error) {
	opts := catOptions{}
	fileName := args[0]

	// Process remaining arguments
	i := 1
	for i < len(args) {
		arg := args[i]

		switch arg {
		case "-f", "--filter":
			if i+1 >= len(args) {
				return "", opts, fmt.Errorf(Err(E20))
			}
			opts.grepPattern = args[i+1]
			i += 2

		case "-i":
			if i+1 >= len(args) {
				return "", opts, fmt.Errorf(Err(E20))
			}
			opts.grepPattern = args[i+1]
			opts.caseInsensitive = true
			i += 2

		default:
			// If we haven't seen a file yet and this doesn't start with -, treat it as the file
			if i == 1 && !strings.HasPrefix(arg, "-") {
				fileName = arg
				i++
			} else {
				return "", opts, fmt.Errorf(ErrCtx(E21, arg))
			}
		}
	}

	return fileName, opts, nil
}

// Modified readFile function from action_cat.go
func (c *CatCommand) readFile(filePath string, opts catOptions) (string, error) {
	// MODIFIED: Use NetworkAwareOpenFile instead of os.Open
	file, err := NetworkAwareOpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf(Err(E4))
		} else if os.IsPermission(err) {
			return "", fmt.Errorf(Err(E3))
		}
		return "", err
	}
	defer file.Close()

	// Check if file is binary
	reader := bufio.NewReader(file)
	peekBytes, _ := reader.Peek(512)
	if len(peekBytes) > 0 {
		if isBinary(peekBytes) {
			return "", fmt.Errorf(Err(E8))
		}
	}

	// Reset reader
	file.Seek(0, 0)
	reader = bufio.NewReader(file)

	var output strings.Builder
	var lineNum int
	scanner := bufio.NewScanner(reader)

	// Set max token size to handle long lines
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Apply grep filter if specified
		if opts.grepPattern != "" {
			if opts.caseInsensitive {
				if !strings.Contains(strings.ToLower(line), strings.ToLower(opts.grepPattern)) {
					continue
				}
			} else {
				if !strings.Contains(line, opts.grepPattern) {
					continue
				}
			}
		}

		output.WriteString(line)
		output.WriteString("\n")
	}

	if err := scanner.Err(); err != nil {
		return output.String(), fmt.Errorf(Err(E10))
	}

	// If grep was used and nothing matched
	if opts.grepPattern != "" && output.Len() == 0 {
		return ErrCtx(E4, opts.grepPattern), nil
	}

	return output.String(), nil
}

func (c *CatCommand) grepFile(file *os.File, opts catOptions) (string, error) {
	scanner := bufio.NewScanner(file)
	var matchedLines []string
	lineNum := 0

	pattern := opts.grepPattern

	// Check if pattern contains wildcards (* or ?)
	hasWildcards := strings.Contains(pattern, "*") || strings.Contains(pattern, "?")

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Determine if line matches
		var matches bool

		if hasWildcards {
			// Use filepath.Match for wildcard matching
			matchLine := line
			matchPattern := pattern

			if opts.caseInsensitive {
				matchLine = strings.ToLower(line)
				matchPattern = strings.ToLower(pattern)
			}

			// filepath.Match does full string matching, but we want substring matching
			// So we'll check if any part of the line matches the pattern
			matches = c.wildcardContains(matchLine, matchPattern)
		} else {
			// Simple substring matching
			matchLine := line
			matchPattern := pattern

			if opts.caseInsensitive {
				matchLine = strings.ToLower(line)
				matchPattern = strings.ToLower(pattern)
			}

			matches = strings.Contains(matchLine, matchPattern)
		}

		if matches {
			// Include line numbers for grep output
			matchedLines = append(matchedLines, fmt.Sprintf("%d:%s", lineNum, line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf(Err(E10))
	}

	if len(matchedLines) == 0 {
		return ErrCtx(E4, opts.grepPattern), nil
	}

	return strings.Join(matchedLines, "\n"), nil
}

// wildcardContains checks if any substring of text matches the pattern
func (c *CatCommand) wildcardContains(text, pattern string) bool {
	// Special case: if pattern is just "*", it matches everything
	if pattern == "*" {
		return true
	}

	// For patterns like *something*, we can optimize by converting to simple contains
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[1:len(pattern)-1], "*") {
		// Pattern is *something* with no other wildcards
		searchStr := pattern[1 : len(pattern)-1]
		return strings.Contains(text, searchStr)
	}

	// For patterns starting with *, we check if text ends with the pattern after *
	if strings.HasPrefix(pattern, "*") && !strings.Contains(pattern[1:], "*") && !strings.Contains(pattern, "?") {
		return strings.HasSuffix(text, pattern[1:])
	}

	// For patterns ending with *, we check if text starts with the pattern before *
	if strings.HasSuffix(pattern, "*") && !strings.Contains(pattern[:len(pattern)-1], "*") && !strings.Contains(pattern, "?") {
		return strings.HasPrefix(text, pattern[:len(pattern)-1])
	}

	// For more complex patterns, use filepath.Match on the entire line
	matched, _ := filepath.Match(pattern, text)
	if matched {
		return true
	}

	// Also try to find if any substring matches (for patterns without leading *)
	if !strings.HasPrefix(pattern, "*") {
		// Check each possible starting position
		for i := 1; i < len(text); i++ {
			if matched, _ := filepath.Match(pattern, text[i:]); matched {
				return true
			}
		}
	}

	return false
}

func isBinary(data []byte) bool {
	// Check for null bytes which are common in binary files
	for _, b := range data {
		if b == 0 {
			return true
		}
	}

	// Check if most bytes are printable ASCII or common whitespace
	printableCount := 0
	for _, b := range data {
		// Printable ASCII range (32-126) plus common whitespace (9-13)
		if (b >= 32 && b <= 126) || (b >= 9 && b <= 13) {
			printableCount++
		}
	}

	// If less than 90% of bytes are printable, consider it binary
	threshold := len(data) * 9 / 10
	return printableCount < threshold
}
