// internal/templates/whoami.go
package templates

// WhoamiTemplate provides template values for whoami commands
type WhoamiTemplate struct {
	*CommandTemplate
}

// GetWhoamiTemplate returns the whoami command template
func GetWhoamiTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command strings
	tpl[IdxWaCmdName] = "whoami"
	tpl[IdxWaWindows] = "windows"

	// Flags
	tpl[IdxWaFlagV] = "-v"
	tpl[IdxWaFlagG] = "-g"

	// Misc
	tpl[IdxWaBackslash] = "\\"

	return &CommandTemplate{
		Version:   1,
		Type:      TypeWhoami,
		Templates: tpl,
	}
}
