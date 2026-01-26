// internal/templates/rm.go
package templates

// GetRmTemplate returns the rm command template for agents
func GetRmTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Flags (short form - server transforms)
	tpl[IdxRmFlagRecursive] = "-r"
	tpl[IdxRmFlagForce] = "-f"

	// Error patterns
	tpl[IdxRmErrPermDenied] = "permission denied"
	tpl[IdxRmErrDirNotEmpty] = "directory not empty"
	tpl[IdxRmErrResourceBusy] = "resource busy"
	tpl[IdxRmErrNotExist] = "does not exist"
	tpl[IdxRmErrIsDirectory] = "is a directory"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeRm,
		Templates: tpl,
		Params:    []string{},
	}
}

// TransformRmFlags transforms long flags to short flags for rm command
func TransformRmFlags(command string) string {
	replacements := []struct{ from, to string }{
		{"--recursive", "-r"},
		{"--force", "-f"},
	}

	result := command
	for _, r := range replacements {
		result = replaceAllOccurrences(result, r.from, r.to)
	}
	return result
}
