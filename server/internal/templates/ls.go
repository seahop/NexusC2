// internal/templates/ls.go
package templates

// GetLsTemplate returns the ls command template for agents
func GetLsTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Windows system paths to filter
	tpl[IdxLsWinSysVolInfo] = "System Volume Information"
	tpl[IdxLsWinRecycleBin] = "$Recycle.Bin"
	tpl[IdxLsWinConfigMsi] = "Config.Msi"
	tpl[IdxLsWinPagefile] = "pagefile.sys"
	tpl[IdxLsWinHiberfil] = "hiberfil.sys"
	tpl[IdxLsWinSwapfile] = "swapfile.sys"
	tpl[IdxLsWinDsStore] = ".DS_Store"
	tpl[IdxLsWinSpotlight] = ".Spotlight-V100"
	tpl[IdxLsWinFseventsd] = ".fseventsd"
	tpl[IdxLsWinTrashes] = ".Trashes"

	// OS identifiers
	tpl[IdxLsOsWindows] = "windows"
	tpl[IdxLsOsLinux] = "linux"
	tpl[IdxLsOsDarwin] = "darwin"

	// Flags (short form - server transforms)
	tpl[IdxLsFlagMaxDepth] = "-d"
	tpl[IdxLsFlagCount] = "-c"
	tpl[IdxLsFlagExclude] = "-e"
	tpl[IdxLsFlagIgnore] = "-i"
	tpl[IdxLsFlagFilter] = "-f"
	tpl[IdxLsFlagAll] = "-a"
	tpl[IdxLsFlagLong] = "-l"

	// File type markers
	tpl[IdxLsTypeDir] = "d"
	tpl[IdxLsTypeFile] = "-"
	tpl[IdxLsTypeSymlink] = "l"

	// Additional Windows system paths
	tpl[IdxLsWinRecovery] = "Recovery"
	tpl[IdxLsWinProgramData] = "ProgramData"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeLs,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformLsFlags transforms long flags to short flags for ls command
func TransformLsFlags(command string) string {
	replacements := []struct{ from, to string }{
		{"--max-depth=", "-d="},
		{"--filter-ignore", "-i"},
		{"--exclude", "-e"},
		{"--filter", "-f"},
		{"--count", "-c"},
		{"--all", "-a"},
		{"--long", "-l"},
	}

	result := command
	for _, r := range replacements {
		result = replaceAllOccurrences(result, r.from, r.to)
	}
	return result
}
