// internal/templates/ps.go
package templates

// GetPsTemplate returns the ps command template for agents
func GetPsTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Proc paths
	tpl[IdxPsProcCmdline] = "/proc/%d/cmdline"
	tpl[IdxPsProcExe] = "/proc/%d/exe"
	tpl[IdxPsProcStat] = "/proc/%d/stat"
	tpl[IdxPsProcStatus] = "/proc/%d/status"
	tpl[IdxPsProcDir] = "/proc"

	// OS identifiers
	tpl[IdxPsOsLinux] = "linux"
	tpl[IdxPsOsWindows] = "windows"
	tpl[IdxPsOsDarwin] = "darwin"

	// Flags (short form - server transforms)
	tpl[IdxPsFlagVerbose] = "-v"
	tpl[IdxPsFlagExtended] = "-x"
	tpl[IdxPsFlagJson] = "-j"
	tpl[IdxPsFlagNoTrunc] = "-n"
	tpl[IdxPsFlagFilter] = "-f"
	tpl[IdxPsFlagUser] = "-u"
	tpl[IdxPsFlagSort] = "-s"

	// Sort values
	tpl[IdxPsSortCpu] = "cpu"
	tpl[IdxPsSortMem] = "mem"
	tpl[IdxPsSortMemory] = "memory"
	tpl[IdxPsSortName] = "name"
	tpl[IdxPsSortUser] = "user"
	tpl[IdxPsSortPid] = "pid"

	// Status values
	tpl[IdxPsStatusName] = "Name:"
	tpl[IdxPsStatusUid] = "Uid:"
	tpl[IdxPsStatusState] = "State:"
	tpl[IdxPsStatusPpid] = "PPid:"
	tpl[IdxPsStatusVmRss] = "VmRSS:"

	// Windows-specific
	tpl[IdxPsRunningAs] = "Running as: "
	tpl[IdxPsBackslash] = "\\"
	tpl[IdxPsImpersonated] = " (impersonated)"

	return &CommandTemplate{
		Version:   2,
		Type:      TypePs,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformPsFlags transforms long flags to short flags for ps command
func TransformPsFlags(command string) string {
	replacements := []struct{ from, to string }{
		{"--no-truncate", "-n"},
		{"--verbose", "-v"},
		{"--extended", "-x"},
		{"--filter", "-f"},
		{"--json", "-j"},
		{"--user", "-u"},
		{"--sort", "-s"},
	}

	result := command
	for _, r := range replacements {
		result = replaceAllOccurrences(result, r.from, r.to)
	}
	return result
}

func replaceAllOccurrences(s, old, new string) string {
	if old == "" || old == new {
		return s
	}
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result = append(result, new...)
			i += len(old)
		} else {
			result = append(result, s[i])
			i++
		}
	}
	return string(result)
}
