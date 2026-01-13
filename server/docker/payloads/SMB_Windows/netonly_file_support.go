// server/docker/payloads/Windows/netonly_file_support.go

//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API for checking drive type
var (
	procGetDriveTypeW = modKernel32.NewProc("GetDriveTypeW")
)

// Drive type constants
const (
	DRIVE_UNKNOWN     = 0
	DRIVE_NO_ROOT_DIR = 1
	DRIVE_REMOVABLE   = 2
	DRIVE_FIXED       = 3
	DRIVE_REMOTE      = 4
	DRIVE_CDROM       = 5
	DRIVE_RAMDISK     = 6
)

// IsNetworkPath checks if a path is a network path (UNC or mapped network drive)
func IsNetworkPath(path string) bool {
	// Check for UNC paths
	if strings.HasPrefix(path, "\\\\") || strings.HasPrefix(path, "//") {
		return true
	}

	// Check if it's a mapped network drive
	if len(path) >= 2 && path[1] == ':' {
		driveLetter := strings.ToUpper(path[:1])
		rootPath := driveLetter + ":\\"

		rootPathPtr, err := syscall.UTF16PtrFromString(rootPath)
		if err != nil {
			return false
		}

		ret, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(rootPathPtr)))
		driveType := uint32(ret)

		return driveType == DRIVE_REMOTE
	}

	return false
}

// PrepareNetworkOperation logs network-only token usage if applicable
// This is called before network operations to inform the user
func PrepareNetworkOperation(path string) string {
	if !IsNetworkPath(path) {
		return ""
	}

	// Check if we have a network-only token active
	if globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		defer globalTokenStore.mu.RUnlock()

		if globalTokenStore.NetOnlyToken != "" {
			metadata := globalTokenStore.Metadata[globalTokenStore.NetOnlyToken]
			return fmt.Sprintf("Using network-only token '%s' (%s\\%s) for: %s\n",
				globalTokenStore.NetOnlyToken,
				metadata.Domain,
				metadata.User,
				path)
		}
	}

	return ""
}

// WrapNetworkFileOperation wraps file operations with network token context
func WrapNetworkFileOperation(path string, operation func() error) error {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	// Log if using network-only token
	if msg := PrepareNetworkOperation(path); msg != "" {
		// fmt.Print(msg)
	}

	// Apply token if needed
	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this operation
			err := ImpersonateLoggedOnUser(netOnlyHandle)
			if err != nil {
				// Try to execute anyway
				return operation()
			}

			// Execute the operation
			opErr := operation()

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return opErr
		}
	}

	// Execute the operation without impersonation
	return operation()
}

// NetworkAwareStatFile stats a file with network token support
func NetworkAwareStatFile(path string) (os.FileInfo, error) {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this specific operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
				return os.Stat(path)
			}

			// Perform the operation
			info, err := os.Stat(path)

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return info, err
		}
	}

	return os.Stat(path)
}

// NetworkAwareReadDir reads a directory with network token support
func NetworkAwareReadDir(path string) ([]os.DirEntry, error) {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this specific operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
				return os.ReadDir(path)
			}

			// Perform the operation
			entries, err := os.ReadDir(path)

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return entries, err
		}
	}

	return os.ReadDir(path)
}

// NetworkAwareOpenFile opens a file with network token support
func NetworkAwareOpenFile(path string, flag int, perm os.FileMode) (*os.File, error) {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this specific operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
				return os.OpenFile(path, flag, perm)
			}

			// Perform the operation
			file, err := os.OpenFile(path, flag, perm)

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return file, err
		}
	}

	return os.OpenFile(path, flag, perm)
}

// NetworkAwareRemove removes a file/directory with network token support
func NetworkAwareRemove(path string) error {
	return WrapNetworkFileOperation(path, func() error {
		return os.Remove(path)
	})
}

// NetworkAwareRemoveAll removes a directory tree with network token support
func NetworkAwareRemoveAll(path string) error {
	return WrapNetworkFileOperation(path, func() error {
		return os.RemoveAll(path)
	})
}

// NetworkAwareMkdirAll creates a directory path with network token support
func NetworkAwareMkdirAll(path string, perm os.FileMode) error {
	return WrapNetworkFileOperation(path, func() error {
		return os.MkdirAll(path, perm)
	})
}

// NetworkAwareReadFile reads a file with network token support
func NetworkAwareReadFile(path string) ([]byte, error) {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this specific operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
				return os.ReadFile(path)
			}

			// Perform the operation
			data, err := os.ReadFile(path)

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return data, err
		}
	}

	return os.ReadFile(path)
}

// NetworkAwareWriteFile writes a file with network token support
func NetworkAwareWriteFile(path string, data []byte, perm os.FileMode) error {
	// Track network resource for later cleanup
	if IsNetworkPath(path) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(path)
	}

	if IsNetworkPath(path) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this specific operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
				return os.WriteFile(path, data, perm)
			}

			// Perform the operation
			err := os.WriteFile(path, data, perm)

			// IMPORTANT: Always revert impersonation after the operation
			RevertToSelf()

			return err
		}
	}

	return os.WriteFile(path, data, perm)
}

// NetworkAwareCopyFile copies a file with network token support
func NetworkAwareCopyFile(src, dst string) error {
	// Track both source and destination if they're network paths
	if IsNetworkPath(src) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(src)
	}
	if IsNetworkPath(dst) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(dst)
	}

	// Apply token if either path is a network path
	if (IsNetworkPath(src) || IsNetworkPath(dst)) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
			} else {
				// Make sure to revert after the operation
				defer RevertToSelf()
			}
		}
	}

	// Read from source
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf(ErrCtx(E10, err.Error()))
	}

	// Get source file info for permissions
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf(ErrCtx(E4, err.Error()))
	}

	// Write to destination
	return os.WriteFile(dst, data, info.Mode())
}

// NetworkAwareMoveFile moves a file with network token support
func NetworkAwareMoveFile(src, dst string) error {
	// Track both source and destination if they're network paths
	if IsNetworkPath(src) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(src)
	}
	if IsNetworkPath(dst) && networkResourceTracker != nil {
		networkResourceTracker.TrackNetworkResource(dst)
	}

	// Apply token if either path is a network path
	if (IsNetworkPath(src) || IsNetworkPath(dst)) && globalTokenStore != nil {
		globalTokenStore.mu.RLock()
		netOnlyHandle := globalTokenStore.NetOnlyHandle
		globalTokenStore.mu.RUnlock()

		if netOnlyHandle != 0 {
			// Apply impersonation for this operation
			impErr := ImpersonateLoggedOnUser(netOnlyHandle)
			if impErr != nil {
				// Try without impersonation
			} else {
				// Make sure to revert after the operation
				defer RevertToSelf()
			}
		}
	}

	// Try rename first (fastest if on same volume)
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Fall back to copy and delete
	err = NetworkAwareCopyFile(src, dst)
	if err != nil {
		return fmt.Errorf(ErrCtx(E11, err.Error()))
	}

	// Delete source
	return os.Remove(src)
}
