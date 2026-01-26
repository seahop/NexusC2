// internal/templates/socks.go
package templates

// GetSocksTemplate returns the socks command template for agents
func GetSocksTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Protocol format strings
	tpl[IdxSocksWssFmt] = "wss://%s:%d%s"

	// SSH constants
	tpl[IdxSocksKeepalive] = "keepalive@golang.org"
	tpl[IdxSocksDirectTcpip] = "direct-tcpip"

	// Actions
	tpl[IdxSocksActionStart] = "start"
	tpl[IdxSocksActionStop] = "stop"

	// Errors
	tpl[IdxSocksErrUnknownChannel] = "unknown channel type"
	tpl[IdxSocksErrLimitReached] = "connection limit reached"

	return &CommandTemplate{
		Version:   2,
		Type:      TypeSocks,
		Templates: tpl,
		Params:    []string{},
	}
}
