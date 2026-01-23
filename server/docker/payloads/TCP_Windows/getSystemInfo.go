// server/docker/payloads/Windows/getSystemInfo.go
//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// SystemInfo represents the collected system information
type SystemInfo struct {
	// Basic process info
	PID      int    `json:"pid"`
	ProcName string `json:"process_name"`

	// System identification
	Username string `json:"username"`
	Hostname string `json:"hostname"`

	// Network info
	IP string `json:"internal_ip"`

	// System details
	Architecture string    `json:"architecture"`
	OS           string    `json:"os"`
	Timestamp    time.Time `json:"timestamp"`

	// Client identification
	ClientID string `json:"client_id"`

	// Random seed
	Seed string `json:"seed"`
}

// SystemInfoReport represents the complete report structure
type SystemInfoReport struct {
	AgentInfo SystemInfo        `json:"agent_info"`
	Metadata  map[string]string `json:"metadata"`
	Status    string            `json:"status"`
	Error     string            `json:"error,omitempty"`
}

// getProcessInfo gets the current process ID and name
func getProcessInfo() (int, string, error) {
	pid := os.Getpid()
	procName := os.Args[0]
	procName = strings.TrimSpace(strings.Split(procName, string(os.PathSeparator))[len(strings.Split(procName, string(os.PathSeparator)))-1])
	return pid, procName, nil
}

// getCurrentUser gets the username of the current process
func getCurrentUser() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}
	return currentUser.Username, nil
}

// getHostname gets the system hostname
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E19, err.Error()))
	}
	return hostname, nil
}

// getArchitecture gets the system architecture
func getArchitecture() string {
	return runtime.GOARCH
}

// getOperatingSystem gets the operating system name
func getOperatingSystem() string {
	return runtime.GOOS
}

// isValidIP checks if the IP meets our criteria
func isValidIP(ip string) bool {
	if ip == "localhost" {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	if ipv4 := parsedIP.To4(); ipv4 != nil {
		if strings.HasPrefix(ipv4.String(), "127.") {
			return false
		}
		if strings.HasPrefix(ipv4.String(), "169.") {
			return false
		}
		return true
	}

	return false
}

// getInternalIP gets the first valid internal IP address
func getInternalIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipStr := ""
			switch v := addr.(type) {
			case *net.IPNet:
				ipStr = v.IP.String()
			case *net.IPAddr:
				ipStr = v.IP.String()
			}

			if isValidIP(ipStr) {
				return ipStr, nil
			}
		}
	}

	return "", fmt.Errorf(Err(E12))
}

// generateSeed creates a random 24-character alphanumeric string
func generateSeed() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 24

	result := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", fmt.Errorf(ErrCtx(E19, err.Error()))
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}

// CollectSystemInfo gathers all system information
func CollectSystemInfo(clientID string) (*SystemInfoReport, error) {
	info := &SystemInfo{
		ClientID:  clientID,
		OS:        getOperatingSystem(),
		Timestamp: time.Now().UTC(),
	}

	var err error

	// Generate seed
	info.Seed, err = generateSeed()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Get process information
	info.PID, info.ProcName, err = getProcessInfo()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Get username
	info.Username, err = getCurrentUser()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Get hostname
	info.Hostname, err = getHostname()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E19, err.Error()))
	}

	// Get IP address
	info.IP, err = getInternalIP()
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E12, err.Error()))
	}

	// Get architecture
	info.Architecture = getArchitecture()

	// Create the full report
	report := &SystemInfoReport{
		AgentInfo: *info,
		Metadata: map[string]string{
			"startup_time": time.Now().UTC().Format(time.RFC3339),
		},
		Status: "active",
	}

	return report, nil
}

// ToJSON converts the SystemInfoReport to a JSON string
func (r *SystemInfoReport) ToJSON() (string, error) {
	jsonBytes, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", fmt.Errorf(ErrCtx(E18, err.Error()))
	}
	return string(jsonBytes), nil
}
