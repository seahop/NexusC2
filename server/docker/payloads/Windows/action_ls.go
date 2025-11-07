// server/docker/payloads/Windows/action_ls.go
//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type LsCommand struct{}

type lsOptions struct {
	humanReadable   bool     // -h
	recursive       bool     // -R
	showHidden      bool     // -a (show hidden files)
	filters         []string // -f patterns (case-sensitive filters)
	filtersIgnore   []string // -i patterns (case-insensitive filters)
	excludePatterns []string // --exclude patterns
	maxDepth        int      // --max-depth=N (limit recursion depth, -1 = unlimited)
	countOnly       bool     // --count (show only counts, not file listing)
}

type dirStats struct {
	files       int
	directories int
}

func (c *LsCommand) Name() string {
	return "ls"
}

// parseFlags parses command line flags for ls
func parseFlags(args []string) ([]string, lsOptions, error) {
	opts := lsOptions{
		maxDepth: -1, // Default to unlimited depth
	}
	var remainingArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]

		if strings.HasPrefix(arg, "-") {
			// Check for --max-depth=N flag
			if strings.HasPrefix(arg, "--max-depth=") {
				depthStr := strings.TrimPrefix(arg, "--max-depth=")
				depth, err := strconv.Atoi(depthStr)
				if err != nil || depth < 0 {
					return nil, opts, fmt.Errorf("invalid max-depth value: %s", depthStr)
				}
				opts.maxDepth = depth
				i++
				continue
			}

			// Check for --count flag
			if arg == "--count" {
				opts.countOnly = true
				i++
				continue
			}

			// Check for --exclude flag
			if arg == "--exclude" {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf("flag %s requires an argument", arg)
				}
				opts.excludePatterns = append(opts.excludePatterns, args[i+1])
				i += 2
				continue
			}

			// Check if it's a flag that requires a value
			if arg == "-f" || arg == "--filter" {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf("flag %s requires an argument", arg)
				}
				opts.filters = append(opts.filters, args[i+1])
				i += 2
				continue
			} else if arg == "-i" || arg == "--filter-ignore" {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf("flag %s requires an argument", arg)
				}
				opts.filtersIgnore = append(opts.filtersIgnore, args[i+1])
				i += 2
				continue
			}

			// Handle single-letter flags that can be combined
			for _, flag := range arg[1:] {
				switch flag {
				case 'h':
					opts.humanReadable = true
				case 'R':
					opts.recursive = true
				case 'a':
					opts.showHidden = true
				default:
					// Check if it's part of a combined flag like -hRf
					// If we hit 'f' or 'i', it needs to be handled separately
					if flag == 'f' || flag == 'i' {
						return nil, opts, fmt.Errorf("flag -%c requires an argument (use it separately)", flag)
					}
					return nil, opts, fmt.Errorf("unknown flag: -%c", flag)
				}
			}
			i++
		} else {
			remainingArgs = append(remainingArgs, arg)
			i++
		}
	}

	return remainingArgs, opts, nil
}

// matchesFilter checks if a name matches the filter patterns
func matchesFilter(name string, opts lsOptions) bool {
	// First check if it's a hidden file and whether we should show it
	if !opts.showHidden && strings.HasPrefix(name, ".") {
		return false
	}

	// Check exclusion patterns first - if excluded, don't show
	for _, excludePattern := range opts.excludePatterns {
		if strings.Contains(strings.ToLower(name), strings.ToLower(excludePattern)) {
			return false
		}
	}

	// If no inclusion filters specified, match everything (that passed hidden and exclusion checks)
	if len(opts.filters) == 0 && len(opts.filtersIgnore) == 0 {
		return true
	}

	// Check if name matches ANY of the inclusion filters (OR logic)
	// Case-sensitive filters
	for _, pattern := range opts.filters {
		if strings.Contains(name, pattern) {
			return true
		}
	}

	// Case-insensitive filters
	nameLower := strings.ToLower(name)
	for _, pattern := range opts.filtersIgnore {
		if strings.Contains(nameLower, strings.ToLower(pattern)) {
			return true
		}
	}

	// Didn't match any inclusion filters
	return false
}

// matchesFilterForDir checks if a directory should be traversed (for exclusion)
func matchesFilterForDir(name string, opts lsOptions) bool {
	// Check if directory is excluded
	for _, excludePattern := range opts.excludePatterns {
		if strings.Contains(strings.ToLower(name), strings.ToLower(excludePattern)) {
			return false
		}
	}
	return true
}

// formatSize formats file size in human-readable format if requested
func formatSize(size int64, humanReadable bool) string {
	if !humanReadable {
		return fmt.Sprintf("%12d", size)
	}

	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%12d B", size)
	}

	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%9.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

func listDirectory(path string, opts lsOptions, currentDepth int, stats *dirStats) (string, error) {
	// MODIFIED: Use NetworkAwareReadDir instead of os.ReadDir
	entries, err := NetworkAwareReadDir(path)
	if err != nil {
		return "", fmt.Errorf("cannot access '%s': %v", path, err)
	}

	// Sort entries: directories first (if sortDirsFirst is true), then alphabetically
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	var output strings.Builder

	// Check if there are any matching entries before printing header
	hasMatchingEntries := false
	for _, entry := range entries {
		if matchesFilter(entry.Name(), opts) {
			hasMatchingEntries = true
			break
		}
	}

	// For count-only mode, just count and recurse
	if opts.countOnly && stats != nil {
		for _, entry := range entries {
			if !matchesFilter(entry.Name(), opts) {
				continue
			}

			if entry.IsDir() {
				stats.directories++
			} else {
				stats.files++
			}

			// Handle recursive counting
			if opts.recursive && entry.IsDir() && (opts.maxDepth == -1 || currentDepth < opts.maxDepth) {
				// Skip hidden directories if -a flag is not set
				if !opts.showHidden && strings.HasPrefix(entry.Name(), ".") {
					continue
				}

				// Skip excluded directories
				if !matchesFilterForDir(entry.Name(), opts) {
					continue
				}

				// Skip system directories on Windows
				if runtime.GOOS == "windows" && currentDepth == 0 {
					name := entry.Name()
					if name == "System Volume Information" || name == "$Recycle.Bin" ||
						name == "Config.Msi" || name == "Recovery" || name == "ProgramData" {
						continue
					}
				}

				subPath := filepath.Join(path, entry.Name())
				_, _ = listDirectory(subPath, opts, currentDepth+1, stats)
				// Ignore errors and continue counting
			}
		}
		return "", nil // Return empty string for count-only mode
	}

	// Only write header if there are matching entries
	if hasMatchingEntries {
		if currentDepth > 0 {
			output.WriteString(fmt.Sprintf("\n%s:\n", filepath.ToSlash(path)))
		}

		output.WriteString("Permissions  Type        Size         Modified Time         Name\n")
		output.WriteString("------------ ----------- ------------ ------------------- ----------------------------------------\n")

		for _, entry := range entries {
			// Skip entries that don't match the filter (including hidden files check)
			if !matchesFilter(entry.Name(), opts) {
				continue
			}

			// Skip system files on Windows root
			if runtime.GOOS == "windows" && currentDepth == 0 {
				name := entry.Name()
				if name == "System Volume Information" || name == "$Recycle.Bin" ||
					name == "pagefile.sys" || name == "hiberfil.sys" || name == "swapfile.sys" {
					continue
				}
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Get permissions string
			perms := formatPermissions(info)

			// Type indicator
			typeStr := "file"
			if info.IsDir() {
				typeStr = "dir "
			}

			// Format size
			sizeStr := formatSize(info.Size(), opts.humanReadable)

			// Format modification time
			modTime := info.ModTime().Format("2006-01-02 15:04:05")

			// Format name (add trailing slash for directories)
			name := info.Name()
			if info.IsDir() {
				name += "/"
			}

			line := fmt.Sprintf("%-12s %-11s %s %s %s\n",
				perms,
				typeStr,
				sizeStr,
				modTime,
				name)
			output.WriteString(line)
		}
	}

	// Handle recursive listing with depth limit
	if opts.recursive && (opts.maxDepth == -1 || currentDepth < opts.maxDepth) {
		for _, entry := range entries {
			if entry.IsDir() {
				// Skip hidden directories if -a flag is not set
				if !opts.showHidden && strings.HasPrefix(entry.Name(), ".") {
					continue
				}

				// Skip excluded directories
				if !matchesFilterForDir(entry.Name(), opts) {
					continue
				}

				// Skip system directories on Windows
				if runtime.GOOS == "windows" && currentDepth == 0 {
					name := entry.Name()
					if name == "System Volume Information" || name == "$Recycle.Bin" ||
						name == "Config.Msi" || name == "Recovery" || name == "ProgramData" {
						continue
					}
				}

				// For recursive listing, we traverse directories within depth limit
				subPath := filepath.Join(path, entry.Name())
				subOutput, err := listDirectory(subPath, opts, currentDepth+1, stats)
				if err != nil {
					continue
				}
				if subOutput != "" {
					output.WriteString(subOutput)
				}
			}
		}
	}

	return output.String(), nil
}

func (c *LsCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	ctx.mu.RLock()
	targetDir := ctx.WorkingDir
	ctx.mu.RUnlock()

	// Parse flags
	remainingArgs, opts, err := parseFlags(args)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: err.Error(),
			Output:      fmt.Sprintf("Error parsing flags: %v\nUsage: ls [-a] [-h] [-R] [--max-depth=N] [--count] [-f pattern]... [-i pattern]... [--exclude pattern]... [path]", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle directory argument if provided
	if len(remainingArgs) > 0 {
		targetPath := filepath.FromSlash(remainingArgs[0])
		if filepath.IsAbs(targetPath) {
			targetDir = targetPath
		} else {
			targetDir = filepath.Join(targetDir, targetPath)
		}
	}

	targetDir = filepath.Clean(targetDir)

	// Verify directory exists and is accessible
	info, err := NetworkAwareStatFile(targetDir)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: err.Error(),
			Output:      fmt.Sprintf("Cannot access directory: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if !info.IsDir() {
		err := fmt.Errorf("not a directory: %s", targetDir)
		return CommandResult{
			Error:       err,
			ErrorString: err.Error(),
			Output:      err.Error(),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Special handling for root directory listing
	if (filepath.Clean(targetDir) == "/" || filepath.Clean(targetDir) == "C:\\") && opts.recursive && opts.maxDepth == -1 {
		// Warn about potentially problematic operation
		fmt.Printf("Warning: Recursive listing of root directory without depth limit may take a very long time.\n")
		fmt.Printf("Consider using --max-depth to limit recursion (e.g., --max-depth=3)\n\n")
	}

	// Initialize stats if counting
	var stats *dirStats
	if opts.countOnly {
		stats = &dirStats{}
	}

	output, err := listDirectory(targetDir, opts, 0, stats)
	if err != nil {
		return CommandResult{
			Error:       err,
			ErrorString: err.Error(),
			Output:      fmt.Sprintf("Error listing directory: %v", err),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle count-only output
	if opts.countOnly {
		if len(opts.filters) > 0 || len(opts.filtersIgnore) > 0 {
			total := stats.files + stats.directories
			patterns := append(opts.filters, opts.filtersIgnore...)
			output = fmt.Sprintf("Matching items for patterns %v: %d (Files: %d, Directories: %d)\n",
				patterns, total, stats.files, stats.directories)
		} else {
			output = fmt.Sprintf("Files: %d\nDirectories: %d\nTotal: %d\n",
				stats.files, stats.directories, stats.files+stats.directories)
		}
	} else if output == "" && (len(opts.filters) > 0 || len(opts.filtersIgnore) > 0) {
		// If filtering is enabled and no results, provide a message
		patterns := append(opts.filters, opts.filtersIgnore...)
		output = fmt.Sprintf("No files matching patterns %v found in %s\n", patterns, targetDir)
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// formatPermissions handles permission formatting
func formatPermissions(info os.FileInfo) string {
	switch runtime.GOOS {
	case "linux", "darwin":
		// Unix-like permission format (e.g., rwxr-xr-x)
		mode := info.Mode()
		var perms strings.Builder

		// File type
		if mode.IsDir() {
			perms.WriteRune('d')
		} else if mode&os.ModeSymlink != 0 {
			perms.WriteRune('l')
		} else {
			perms.WriteRune('-')
		}

		// Owner permissions
		perms.WriteRune(rwx(mode, 6, 'r'))
		perms.WriteRune(rwx(mode, 7, 'w'))
		perms.WriteRune(rwx(mode, 8, 'x'))

		// Group permissions
		perms.WriteRune(rwx(mode, 3, 'r'))
		perms.WriteRune(rwx(mode, 4, 'w'))
		perms.WriteRune(rwx(mode, 5, 'x'))

		// Others permissions
		perms.WriteRune(rwx(mode, 0, 'r'))
		perms.WriteRune(rwx(mode, 1, 'w'))
		perms.WriteRune(rwx(mode, 2, 'x'))

		return perms.String()

	case "windows":
		mode := info.Mode()
		attrs := make([]string, 4)

		// Initialize with dashes
		for i := range attrs {
			attrs[i] = "-"
		}

		// Check if writable (if not writable, mark as read-only)
		if mode&0200 == 0 {
			attrs[0] = "R"
		}
		// Hidden (check if name starts with .)
		if strings.HasPrefix(info.Name(), ".") {
			attrs[1] = "H"
		}
		// Directory
		if mode.IsDir() {
			attrs[3] = "D"
		}

		return strings.Join(attrs, "")

	default:
		return "unknown"
	}
}

// Helper function for Unix permissions
func rwx(mode os.FileMode, shift uint, c rune) rune {
	if mode&(1<<shift) != 0 {
		return c
	}
	return '-'
}
