// internal/templates/socks_http.go
package templates

// GetSocksHTTPTemplate returns the HTTP-based SOCKS proxy template for agents
func GetSocksHTTPTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// Actions
	tpl[IdxSocksHTTPActionConnect] = "connect"
	tpl[IdxSocksHTTPActionData] = "data"
	tpl[IdxSocksHTTPActionClose] = "close"

	// Status responses
	tpl[IdxSocksHTTPStatusConnected] = "connected"
	tpl[IdxSocksHTTPStatusData] = "data"
	tpl[IdxSocksHTTPStatusClosed] = "closed"
	tpl[IdxSocksHTTPStatusError] = "error"

	// JSON field keys
	tpl[IdxSocksHTTPFieldSid] = "sid"
	tpl[IdxSocksHTTPFieldStatus] = "st"
	tpl[IdxSocksHTTPFieldData] = "d"
	tpl[IdxSocksHTTPFieldError] = "err"

	// Error messages
	tpl[IdxSocksHTTPErrNoData] = "no data provided"
	tpl[IdxSocksHTTPErrParseFailed] = "failed to parse command data"
	tpl[IdxSocksHTTPErrUnknownAct] = "unknown action"
	tpl[IdxSocksHTTPErrSessNotFound] = "session not found"

	return &CommandTemplate{
		Version:   1,
		Type:      TypeSocksHTTP,
		Templates: tpl,
		Params:    []string{},
	}
}
