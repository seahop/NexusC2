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

// Ls flag strings (constructed to avoid static signatures)
var (
	// Flag arguments
	lsMaxDepthPfx  = string([]byte{0x2d, 0x2d, 0x6d, 0x61, 0x78, 0x2d, 0x64, 0x65, 0x70, 0x74, 0x68, 0x3d})                         // --max-depth=
	lsCount        = string([]byte{0x2d, 0x2d, 0x63, 0x6f, 0x75, 0x6e, 0x74})                                                       // --count
	lsExclude      = string([]byte{0x2d, 0x2d, 0x65, 0x78, 0x63, 0x6c, 0x75, 0x64, 0x65})                                           // --exclude
	lsFilterLong   = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72})                                                 // --filter
	lsFilterIgnore = string([]byte{0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2d, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65})       // --filter-ignore
	lsFilterShort  = string([]byte{0x2d, 0x66})                                                                                     // -f
	lsFilterIShort = string([]byte{0x2d, 0x69})                                                                                     // -i

	// Size format units
	lsSizeUnits = string([]byte{0x4b, 0x4d, 0x47, 0x54, 0x50, 0x45}) // KMGTPE

	// Windows system paths (skipped during listing)
	lsSysVolInfo  = string([]byte{0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x20, 0x56, 0x6f, 0x6c, 0x75, 0x6d, 0x65, 0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x69, 0x6f, 0x6e}) // System Volume Information
	lsRecycleBin  = string([]byte{0x24, 0x52, 0x65, 0x63, 0x79, 0x63, 0x6c, 0x65, 0x2e, 0x42, 0x69, 0x6e})                                                                               // $Recycle.Bin
	lsConfigMsi   = string([]byte{0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4d, 0x73, 0x69})                                                                                           // Config.Msi
	lsRecovery    = string([]byte{0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79})                                                                                                       // Recovery
	lsProgramData = string([]byte{0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x44, 0x61, 0x74, 0x61})                                                                                     // ProgramData
	lsPagefile    = string([]byte{0x70, 0x61, 0x67, 0x65, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x73, 0x79, 0x73})                                                                               // pagefile.sys
	lsHiberfile   = string([]byte{0x68, 0x69, 0x62, 0x65, 0x72, 0x66, 0x69, 0x6c, 0x2e, 0x73, 0x79, 0x73})                                                                               // hiberfil.sys
	lsSwapfile    = string([]byte{0x73, 0x77, 0x61, 0x70, 0x66, 0x69, 0x6c, 0x65, 0x2e, 0x73, 0x79, 0x73})                                                                               // swapfile.sys

	// OS names
	lsOSWindows = string([]byte{0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73}) // windows
	lsOSLinux   = string([]byte{0x6c, 0x69, 0x6e, 0x75, 0x78})             // linux
	lsOSDarwin  = string([]byte{0x64, 0x61, 0x72, 0x77, 0x69, 0x6e})       // darwin

	// Windows root path
	lsWinRoot = string([]byte{0x43, 0x3a, 0x5c}) // C:\
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
			if strings.HasPrefix(arg, lsMaxDepthPfx) {
				depthStr := strings.TrimPrefix(arg, lsMaxDepthPfx)
				depth, err := strconv.Atoi(depthStr)
				if err != nil || depth < 0 {
					return nil, opts, fmt.Errorf(ErrCtx(E22, depthStr))
				}
				opts.maxDepth = depth
				i++
				continue
			}

			// Check for --count flag
			if arg == lsCount {
				opts.countOnly = true
				i++
				continue
			}

			// Check for --exclude flag
			if arg == lsExclude {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf(Err(E20))
				}
				opts.excludePatterns = append(opts.excludePatterns, args[i+1])
				i += 2
				continue
			}

			// Check if it's a flag that requires a value
			if arg == lsFilterShort || arg == lsFilterLong {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf(Err(E20))
				}
				opts.filters = append(opts.filters, args[i+1])
				i += 2
				continue
			} else if arg == lsFilterIShort || arg == lsFilterIgnore {
				if i+1 >= len(args) {
					return nil, opts, fmt.Errorf(Err(E20))
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
						return nil, opts, fmt.Errorf(ErrCtx(E20, string(flag)))
					}
					return nil, opts, fmt.Errorf(ErrCtx(E21, string(flag)))
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

	return fmt.Sprintf("%9.1f %cB", float64(size)/float64(div), lsSizeUnits[exp])
}

func listDirectory(path string, opts lsOptions, currentDepth int, stats *dirStats) (string, error) {
	// MODIFIED: Use NetworkAwareReadDir instead of os.ReadDir
	entries, err := NetworkAwareReadDir(path)
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E4, path))
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
				if runtime.GOOS == lsOSWindows && currentDepth == 0 {
					name := entry.Name()
					if name == lsSysVolInfo || name == lsRecycleBin ||
						name == lsConfigMsi || name == lsRecovery || name == lsProgramData {
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

		// Count matching entries for table header
		matchCount := 0
		for _, e := range entries {
			if matchesFilter(e.Name(), opts) {
				matchCount++
			}
		}
		output.WriteString(Table(TLS, matchCount) + "\n")

		for _, entry := range entries {
			// Skip entries that don't match the filter (including hidden files check)
			if !matchesFilter(entry.Name(), opts) {
				continue
			}

			// Skip system files on Windows root
			if runtime.GOOS == lsOSWindows && currentDepth == 0 {
				name := entry.Name()
				if name == lsSysVolInfo || name == lsRecycleBin ||
					name == lsPagefile || name == lsHiberfile || name == lsSwapfile {
					continue
				}
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Get permissions string
			perms := formatPermissions(info)

			// Type indicator (0=file, 1=dir)
			typeStr := RFile
			if info.IsDir() {
				typeStr = RDir
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
				if runtime.GOOS == lsOSWindows && currentDepth == 0 {
					name := entry.Name()
					if name == lsSysVolInfo || name == lsRecycleBin ||
						name == lsConfigMsi || name == lsRecovery || name == lsProgramData {
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
			Output:      Err(E2),
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
			ErrorString: Err(E4),
			Output:      ErrCtx(E4, targetDir),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	if !info.IsDir() {
		return CommandResult{
			Error:       fmt.Errorf(Err(E7)),
			ErrorString: Err(E7),
			Output:      ErrCtx(E7, targetDir),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Special handling for root directory listing
	if (filepath.Clean(targetDir) == "/" || filepath.Clean(targetDir) == lsWinRoot) && opts.recursive && opts.maxDepth == -1 {
		// Warn about potentially problematic operation
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
			ErrorString: Err(E10),
			Output:      ErrCtx(E10, targetDir),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Handle count-only output - format: T:M:files,dirs
	if opts.countOnly {
		output = fmt.Sprintf("%s%d,%d", TLSCount, stats.files, stats.directories)
	} else if output == "" && (len(opts.filters) > 0 || len(opts.filtersIgnore) > 0) {
		// If filtering is enabled and no results
		output = SuccCtx(S0, "0")
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
	case lsOSLinux, lsOSDarwin:
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

	case lsOSWindows:
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
