// server/docker/payloads/Linux/pty_helper.go

//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"os/exec"

	"github.com/creack/pty"
)

// PTYHelper provides common PTY functionality for fallback
type PTYHelper struct {
	timeout time.Duration
}

// ExecuteWithSudo runs a command with sudo using PTY (stateless fallback)
func (p *PTYHelper) ExecuteWithSudo(password, command, workingDir string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	// Prepare sudo command
	cmd := exec.CommandContext(ctx, "sudo", "-S", "-p", "Password:", "sh", "-c", command)
	cmd.Dir = workingDir

	// Start with PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return "", 1, fmt.Errorf(ErrCtx(E37, err.Error()))
	}
	defer ptmx.Close()

	// Handle password prompt in goroutine
	passwordSent := false
	outputBuffer := &bytes.Buffer{}
	errorChan := make(chan error, 1)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				if err != io.EOF {
					if outputBuffer.Len() == 0 {
						errorChan <- err
					}
				}
				return
			}

			output := string(buf[:n])

			// Check for password prompt
			if !passwordSent && strings.Contains(output, "Password:") {
				_, err := ptmx.Write([]byte(password + "\n"))
				if err != nil {
					errorChan <- fmt.Errorf(ErrCtx(E11, err.Error()))
					return
				}
				passwordSent = true
				continue
			}

			// Check for wrong password
			if strings.Contains(output, "Sorry, try again") ||
				strings.Contains(output, "incorrect password") {
				errorChan <- fmt.Errorf(Err(E3))
				return
			}

			// Add to output buffer (skip password prompts)
			if !strings.Contains(output, "Password:") {
				outputBuffer.Write(buf[:n])
			}
		}
	}()

	// Wait for command to complete
	exitCode := 0
	err = cmd.Wait()

	// Check for errors from goroutine
	select {
	case goroutineErr := <-errorChan:
		if goroutineErr != nil && outputBuffer.Len() == 0 {
			return outputBuffer.String(), 1, goroutineErr
		}
	default:
	}

	// If we got output, consider it successful
	if outputBuffer.Len() > 0 {
		return strings.TrimSpace(outputBuffer.String()), 0, nil
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return outputBuffer.String(), 124, fmt.Errorf(Err(E6))
		} else {
			exitCode = 1
		}
	}

	return outputBuffer.String(), exitCode, err
}

// SudoSession represents a sudo session (can be stateful or stateless)
type SudoSession struct {
	cmd          *exec.Cmd
	pty          *os.File
	isActive     bool
	createdAt    time.Time
	mu           sync.Mutex
	targetUser   string
	password     string // Keep for fallback if needed
	workingDir   string
	currentDir   string            // Track current directory for stateful mode
	environment  map[string]string // Track environment for stateful mode
	promptMarker string            // Unique marker to detect command completion
	readBuffer   []byte            // Buffer for reading
	useStateful  bool              // Whether to use stateful execution
}

// StartSudoSessionAsUser creates a new sudo session
func StartSudoSessionAsUser(password, targetUser, workingDir string) (*SudoSession, error) {
	var cmd *exec.Cmd
	if targetUser == "root" || targetUser == "" {
		cmd = exec.Command("sudo", "-S", "su", "-")
	} else {
		cmd = exec.Command("sudo", "-S", "su", "-", targetUser)
	}

	if workingDir != "" {
		cmd.Dir = workingDir
	}

	// Start with PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf(ErrCtx(E37, err.Error()))
	}

	session := &SudoSession{
		cmd:          cmd,
		pty:          ptmx,
		isActive:     true,
		createdAt:    time.Now(),
		targetUser:   targetUser,
		password:     password,
		workingDir:   workingDir,
		currentDir:   workingDir, // Initialize current directory
		environment:  make(map[string]string),
		promptMarker: fmt.Sprintf("___MARKER_%d___", time.Now().UnixNano()),
		readBuffer:   make([]byte, 4096),
		useStateful:  false, // Start with stateless for reliability
	}

	// Handle authentication with timeout
	authDone := make(chan error, 1)
	go func() {
		// Read initial output
		buf := make([]byte, 1024)
		ptmx.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := ptmx.Read(buf)
		ptmx.SetReadDeadline(time.Time{})

		if err != nil {
			authDone <- fmt.Errorf(ErrCtx(E10, err.Error()))
			return
		}

		output := string(buf[:n])

		// Send password if prompted
		if strings.Contains(output, "Password:") || strings.Contains(output, "password") {
			_, err = ptmx.Write([]byte(password + "\n"))
			if err != nil {
				authDone <- fmt.Errorf(ErrCtx(E11, err.Error()))
				return
			}

			// Check for success
			time.Sleep(500 * time.Millisecond)
			ptmx.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _ = ptmx.Read(buf)
			ptmx.SetReadDeadline(time.Time{})

			if n > 0 {
				authResult := string(buf[:n])
				if strings.Contains(authResult, "Sorry") || strings.Contains(authResult, "incorrect") {
					authDone <- fmt.Errorf(Err(E3))
					return
				}
			}
		}

		authDone <- nil
	}()

	// Wait for authentication with timeout
	select {
	case err := <-authDone:
		if err != nil {
			session.Close()
			return nil, err
		}
	case <-time.After(3 * time.Second):
		// Authentication timeout - continuing anyway
	}

	return session, nil
}

// StartSudoSession creates a new sudo session (defaults to root)
func StartSudoSession(password, workingDir string) (*SudoSession, error) {
	return StartSudoSessionAsUser(password, "root", workingDir)
}

// EnableStatefulMode tries to set up the session for stateful execution
// For now, we'll simulate stateful mode by tracking state ourselves
func (s *SudoSession) EnableStatefulMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isActive {
		return fmt.Errorf(Err(E4))
	}

	// Instead of trying to set up PTY prompts which can be unreliable,
	// we'll track state ourselves and apply it to each command
	s.useStateful = true

	// Get initial working directory
	helper := &PTYHelper{timeout: 2 * time.Second}
	output, _, err := helper.ExecuteWithSudo(s.password, "pwd", s.workingDir)
	if err == nil && output != "" {
		s.currentDir = strings.TrimSpace(output)
	}

	return nil
}

// ExecuteCommand executes a command (with simulated state if enabled)
func (s *SudoSession) ExecuteCommand(command string, timeout time.Duration) (string, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isActive {
		return "", 1, fmt.Errorf(Err(E4))
	}

	// Handle stateful mode by tracking and applying state
	if s.useStateful {
		return s.executeStatefulSimulated(command, timeout)
	}

	// Stateless execution (default)
	helper := &PTYHelper{timeout: timeout}
	output, exitCode, err := helper.ExecuteWithSudo(s.password, command, s.workingDir)

	// Suppress PTY errors if we got output
	if output != "" && err != nil && strings.Contains(err.Error(), "ptmx") {
		return output, 0, nil
	}

	return output, exitCode, err
}

// executeStatefulSimulated simulates stateful execution by tracking state
func (s *SudoSession) executeStatefulSimulated(command string, timeout time.Duration) (string, int, error) {
	trimmedCmd := strings.TrimSpace(command)

	// Handle cd commands specially
	if strings.HasPrefix(trimmedCmd, "cd ") {
		newDir := strings.TrimSpace(strings.TrimPrefix(trimmedCmd, "cd"))

		// Handle special cases
		if newDir == "" || newDir == "~" {
			newDir = "~"
		} else if !strings.HasPrefix(newDir, "/") && !strings.HasPrefix(newDir, "~") {
			// Relative path - append to current directory
			if s.currentDir != "" {
				newDir = s.currentDir + "/" + newDir
			}
		}

		// Execute cd and verify it worked
		helper := &PTYHelper{timeout: timeout}
		cdCmd := fmt.Sprintf("cd %s && pwd", newDir)
		output, exitCode, err := helper.ExecuteWithSudo(s.password, cdCmd, s.workingDir)

		if err == nil && exitCode == 0 && output != "" {
			// Update current directory
			s.currentDir = strings.TrimSpace(output)
			return "", 0, nil // cd typically has no output
		}

		return output, exitCode, err
	}

	// Handle export commands
	if strings.HasPrefix(trimmedCmd, "export ") {
		varDef := strings.TrimPrefix(trimmedCmd, "export ")
		parts := strings.SplitN(varDef, "=", 2)
		if len(parts) == 2 {
			varName := strings.TrimSpace(parts[0])
			varValue := strings.Trim(strings.TrimSpace(parts[1]), "'\"")
			s.environment[varName] = varValue
			return "", 0, nil // export typically has no output
		}
	}

	// For other commands, build a command that includes state
	fullCommand := command

	// Apply environment variables
	if len(s.environment) > 0 {
		var exports []string
		for k, v := range s.environment {
			exports = append(exports, fmt.Sprintf("export %s='%s'", k, v))
		}
		fullCommand = strings.Join(exports, " && ") + " && " + command
	}

	// Apply current directory
	if s.currentDir != "" && s.currentDir != s.workingDir {
		fullCommand = fmt.Sprintf("cd %s && %s", s.currentDir, fullCommand)
	}

	// Execute with state applied
	helper := &PTYHelper{timeout: timeout}
	output, exitCode, err := helper.ExecuteWithSudo(s.password, fullCommand, s.workingDir)

	// Suppress PTY errors if we got output
	if output != "" && err != nil && strings.Contains(err.Error(), "ptmx") {
		return output, 0, nil
	}

	return output, exitCode, err
}

// SetStateful enables or disables stateful execution
func (s *SudoSession) SetStateful(stateful bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.useStateful = stateful

	// Reset state tracking if disabling
	if !stateful {
		s.currentDir = s.workingDir
		s.environment = make(map[string]string)
	}
}

// Close terminates the session
func (s *SudoSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isActive {
		return nil
	}

	s.isActive = false

	// Send exit command
	if s.pty != nil {
		s.pty.Write([]byte("exit\n"))
		time.Sleep(100 * time.Millisecond)
		s.pty.Close()
	}

	// Kill process if still running
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
		s.cmd.Wait()
	}

	// Clear password from memory
	s.password = ""

	return nil
}

// GetInfo returns session information
func (s *SudoSession) GetInfo() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isActive {
		return Err(E30)
	}

	uptime := time.Since(s.createdAt)
	user := s.targetUser
	if user == "" {
		user = "root"
	}

	pid := 0
	if s.cmd != nil && s.cmd.Process != nil {
		pid = s.cmd.Process.Pid
	}

	mode := "stateless (reliable)"
	if s.useStateful {
		mode = fmt.Sprintf("stateful (simulated, pwd: %s)", s.currentDir)
	}

	return fmt.Sprintf("Active session for user '%s' (PID: %d, Mode: %s, Uptime: %v)",
		user, pid, mode, uptime.Round(time.Second))
}
