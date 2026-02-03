// internal/templates/socks_http.go
package templates

// GetSocksHTTPTemplate returns the HTTP-based SOCKS proxy template for agents
// Supports both TCP CONNECT and UDP ASSOCIATE
func GetSocksHTTPTemplate() *CommandTemplate {
	tpl := make([]string, MaxTemplateSize)

	// TCP Actions
	tpl[IdxSocksHTTPActionConnect] = "connect"
	tpl[IdxSocksHTTPActionData] = "data"
	tpl[IdxSocksHTTPActionClose] = "close"

	// TCP Status responses
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

	// UDP Actions
	tpl[IdxSocksHTTPActionUDPAssoc] = "udp_associate"
	tpl[IdxSocksHTTPActionUDPData] = "udp_data"
	tpl[IdxSocksHTTPActionUDPClose] = "udp_close"

	// UDP Status responses
	tpl[IdxSocksHTTPStatusUDPReady] = "udp_ready"
	tpl[IdxSocksHTTPStatusUDPData] = "udp_data"
	tpl[IdxSocksHTTPStatusUDPClosed] = "udp_closed"

	// UDP JSON field keys
	tpl[IdxSocksHTTPFieldDestAddr] = "da"
	tpl[IdxSocksHTTPFieldDestPort] = "dp"
	tpl[IdxSocksHTTPFieldFrag] = "fg"
	tpl[IdxSocksHTTPFieldAtyp] = "at"

	return &CommandTemplate{
		Version:   2, // Bump version for UDP support
		Type:      TypeSocksHTTP,
		Templates: tpl,
		Params:    []string{},
	}
}
