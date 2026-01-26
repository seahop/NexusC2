// internal/templates/shell.go
package templates

// GetShellTemplate returns the shell command template for Linux/Darwin agents
func GetShellTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Shell paths
	tpl[IdxShellPathBinBash] = "/bin/bash"
	tpl[IdxShellPathBinZsh] = "/bin/zsh"
	tpl[IdxShellPathBinSh] = "/bin/sh"
	tpl[IdxShellPathUsrBinBash] = "/usr/bin/bash"
	tpl[IdxShellPathUsrBinZsh] = "/usr/bin/zsh"
	tpl[IdxShellPathUsrBinSh] = "/usr/bin/sh"
	tpl[IdxShellFallback] = "sh"

	// Environment
	tpl[IdxShellEnvVar] = "SHELL"

	// Shell arguments
	tpl[IdxShellArgC] = "-c"

	// Flags (short form)
	tpl[IdxShellFlagSudo] = "-s"
	tpl[IdxShellFlagTimeout] = "-t"

	// Output markers
	tpl[IdxShellStderrMarker] = "[STDERR]\n"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeShell,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformShellFlags transforms long flags to short flags for shell command
// Returns the transformed command string
func TransformShellFlags(command string) string {
	// Transform --sudo to -s, --timeout to -t
	result := command

	// Replace long flags with short ones
	// Order matters - longer strings first
	replacements := []struct{ from, to string }{
		{"--timeout", "-t"},
		{"--sudo", "-s"},
	}

	for _, r := range replacements {
		result = replaceFlag(result, r.from, r.to)
	}

	return result
}

// replaceFlag replaces a flag in the command string
func replaceFlag(command, from, to string) string {
	// Simple string replacement - flags are space-delimited
	result := command

	// Replace with space before and after
	result = stringReplace(result, " "+from+" ", " "+to+" ")
	// Replace at end of string
	if len(result) >= len(from) && result[len(result)-len(from):] == from {
		result = result[:len(result)-len(from)] + to
	}
	// Replace with space before only (flag followed by value)
	result = stringReplace(result, " "+from, " "+to)

	return result
}

// stringReplace is a simple string replacement without importing strings package
func stringReplace(s, old, new string) string {
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
