// internal/templates/download.go
package templates

// DownloadTemplate provides template values for download commands
type DownloadTemplate struct {
	*CommandTemplate
}

// GetDownloadTemplate returns the download command template
func GetDownloadTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Command strings
	tpl[IdxDlCmdName] = "download"
	tpl[IdxDlOSWindows] = "windows"
	tpl[IdxDlCmdPrefix] = "download "

	// Output format strings
	tpl[IdxDlChunkFmt] = "\nS4:"
	tpl[IdxDlPipeSep] = "|"
	tpl[IdxDlSlash] = "/"

	// Windows-specific
	tpl[IdxDlAsPrefix] = "Downloading as "
	tpl[IdxDlBackslash] = "\\"
	tpl[IdxDlNewline] = "\n"

	return &CommandTemplate{
		Version:   1,
		Type:      TypeDownload,
		Templates: tpl,
	}
}
