// server/cmd/logviewer/main.go
package main

import (
	"bufio"
	"c2/internal/common/logging"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	// Command line flags - backward compatible plus new options
	var (
		// Original flags (backward compatible)
		logDir      = flag.String("dir", "/app/logs/commands", "Log directory path")
		logFile     = flag.String("file", "", "Specific log file to analyze (default: today's log)")
		agentID     = flag.String("agent", "", "Filter by agent ID")
		outputJSON  = flag.Bool("json", false, "Output as JSON")
		showStats   = flag.Bool("stats", false, "Show statistics")
		showPending = flag.Bool("pending", false, "Show only pending commands")
		follow      = flag.Bool("follow", false, "Follow log file (like tail -f)")

		// New enhanced flags
		hostname    = flag.String("host", "", "Filter by hostname")
		ip          = flag.String("ip", "", "Filter by IP (internal or external)")
		username    = flag.String("user", "", "Filter by username")
		commandType = flag.String("type", "", "Filter by command type (ls,pwd,bof,etc)")
		osFilter    = flag.String("os", "", "Filter by OS")
		sessionID   = flag.String("session", "", "Filter by session ID")

		// Output options
		format     = flag.String("format", "text", "Output format: text,json,csv,table")
		verbose    = flag.Bool("v", false, "Verbose output (show all fields)")
		showAgents = flag.Bool("agents", false, "Show unique agents summary")
		showErrors = flag.Bool("errors", false, "Show errors only")

		// Date range
		dateFrom = flag.String("from", "", "Start date (YYYY-MM-DD)")
		dateTo   = flag.String("to", "", "End date (YYYY-MM-DD)")

		// Sorting
		sortBy  = flag.String("sort", "time", "Sort by: time,agent,host,ip,user,command")
		reverse = flag.Bool("reverse", false, "Reverse sort order")
	)
	flag.Parse()

	// Determine log files to process
	logPaths := getLogFiles(*logDir, *logFile, *dateFrom, *dateTo)

	if len(logPaths) == 0 {
		log.Fatalf("No log files found")
	}

	if *follow {
		followLog(logPaths[len(logPaths)-1], *agentID, *hostname, *ip)
	} else {
		analyzeLog(logPaths, &FilterOptions{
			AgentID:     *agentID,
			Hostname:    *hostname,
			IP:          *ip,
			Username:    *username,
			CommandType: *commandType,
			OS:          *osFilter,
			SessionID:   *sessionID,
			ShowPending: *showPending,
			ShowErrors:  *showErrors,
		}, &OutputOptions{
			Format:     *format,
			OutputJSON: *outputJSON,
			Verbose:    *verbose,
			ShowStats:  *showStats,
			ShowAgents: *showAgents,
			SortBy:     *sortBy,
			Reverse:    *reverse,
		})
	}
}

type FilterOptions struct {
	AgentID     string
	Hostname    string
	IP          string
	Username    string
	CommandType string
	OS          string
	SessionID   string
	ShowPending bool
	ShowErrors  bool
}

type OutputOptions struct {
	Format     string
	OutputJSON bool
	Verbose    bool
	ShowStats  bool
	ShowAgents bool
	SortBy     string
	Reverse    bool
}

func getLogFiles(logDir, specificFile, dateFrom, dateTo string) []string {
	var files []string

	if specificFile != "" {
		files = append(files, specificFile)
	} else {
		// Get date range
		startDate := time.Now().AddDate(0, 0, -7) // Default: last 7 days
		endDate := time.Now()

		if dateFrom != "" {
			if t, err := time.Parse("2006-01-02", dateFrom); err == nil {
				startDate = t
			}
		}
		if dateTo != "" {
			if t, err := time.Parse("2006-01-02", dateTo); err == nil {
				endDate = t
			}
		}

		// Find log files in date range
		for d := startDate; !d.After(endDate); d = d.AddDate(0, 0, 1) {
			filename := fmt.Sprintf("commands_%s.log", d.Format("2006-01-02"))
			filepath := filepath.Join(logDir, filename)
			if _, err := os.Stat(filepath); err == nil {
				files = append(files, filepath)
			}
		}

		// If no date range specified and no files found, use today's file
		if len(files) == 0 {
			todayFile := filepath.Join(logDir, fmt.Sprintf("commands_%s.log", time.Now().Format("2006-01-02")))
			if _, err := os.Stat(todayFile); err == nil {
				files = append(files, todayFile)
			}
		}
	}

	return files
}

func analyzeLog(logPaths []string, filters *FilterOptions, output *OutputOptions) {
	// Collect all entries
	var allEntries []logging.LogEntry
	agentMap := make(map[string]*AgentInfo)

	for _, logPath := range logPaths {
		entries, err := loadLogFile(logPath)
		if err != nil {
			log.Printf("Warning: Failed to load %s: %v", logPath, err)
			continue
		}
		allEntries = append(allEntries, entries...)

		// Build agent map
		for _, entry := range entries {
			if entry.AgentID != "" {
				updateAgentMap(agentMap, &entry)
			}
		}
	}

	// Apply filters
	filtered := applyFilters(allEntries, filters)

	// Sort entries
	sortEntries(filtered, output.SortBy, output.Reverse)

	// Create correlator for statistics
	correlator := logging.NewLogCorrelator()
	for _, entry := range filtered {
		correlator.ProcessEntry(entry)
	}

	// Output based on options
	if output.ShowStats {
		showStatistics(correlator, agentMap)
	} else if output.ShowAgents {
		showAgentSummary(agentMap)
	} else {
		outputEntries(filtered, correlator, output)
	}
}

func loadLogFile(logPath string) ([]logging.LogEntry, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []logging.LogEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry logging.LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // Skip malformed entries
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

type AgentInfo struct {
	AgentID      string
	Hostname     string
	ExternalIP   string
	InternalIP   string
	Username     string
	OS           string
	Arch         string
	FirstSeen    time.Time
	LastSeen     time.Time
	CommandCount int
	Sessions     []string
}

func updateAgentMap(agentMap map[string]*AgentInfo, entry *logging.LogEntry) {
	agent, exists := agentMap[entry.AgentID]
	if !exists {
		agent = &AgentInfo{
			AgentID:   entry.AgentID,
			FirstSeen: entry.Timestamp,
			Sessions:  make([]string, 0),
		}
		agentMap[entry.AgentID] = agent
	}

	// Update fields
	if entry.Hostname != "" {
		agent.Hostname = entry.Hostname
	}
	if entry.ExternalIP != "" {
		agent.ExternalIP = entry.ExternalIP
	}
	if entry.InternalIP != "" {
		agent.InternalIP = entry.InternalIP
	}
	if entry.Username != "" {
		agent.Username = entry.Username
	}
	if entry.OS != "" {
		agent.OS = entry.OS
	}
	if entry.Arch != "" {
		agent.Arch = entry.Arch
	}

	agent.LastSeen = entry.Timestamp
	if entry.Type == "command" {
		agent.CommandCount++
	}

	// Track sessions
	if entry.SessionID != "" {
		found := false
		for _, s := range agent.Sessions {
			if s == entry.SessionID {
				found = true
				break
			}
		}
		if !found {
			agent.Sessions = append(agent.Sessions, entry.SessionID)
		}
	}
}

func applyFilters(entries []logging.LogEntry, filters *FilterOptions) []logging.LogEntry {
	var filtered []logging.LogEntry

	for _, entry := range entries {
		// Apply filters
		if filters.AgentID != "" && !strings.Contains(entry.AgentID, filters.AgentID) {
			continue
		}
		if filters.Hostname != "" && !strings.Contains(strings.ToLower(entry.Hostname), strings.ToLower(filters.Hostname)) {
			continue
		}
		if filters.IP != "" && !strings.Contains(entry.ExternalIP, filters.IP) && !strings.Contains(entry.InternalIP, filters.IP) {
			continue
		}
		if filters.Username != "" && !strings.Contains(strings.ToLower(entry.Username), strings.ToLower(filters.Username)) {
			continue
		}
		if filters.CommandType != "" && !strings.Contains(strings.ToLower(entry.CommandType), strings.ToLower(filters.CommandType)) {
			continue
		}
		if filters.OS != "" && !strings.Contains(strings.ToLower(entry.OS), strings.ToLower(filters.OS)) {
			continue
		}
		if filters.SessionID != "" && !strings.Contains(entry.SessionID, filters.SessionID) {
			continue
		}
		if filters.ShowErrors && entry.Type != "error" {
			continue
		}
		if filters.ShowPending && entry.Type != "command" {
			continue
		}

		filtered = append(filtered, entry)
	}

	return filtered
}

func sortEntries(entries []logging.LogEntry, sortBy string, reverse bool) {
	switch sortBy {
	case "agent":
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].AgentID > entries[j].AgentID
			}
			return entries[i].AgentID < entries[j].AgentID
		})
	case "host":
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].Hostname > entries[j].Hostname
			}
			return entries[i].Hostname < entries[j].Hostname
		})
	case "ip":
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].ExternalIP > entries[j].ExternalIP
			}
			return entries[i].ExternalIP < entries[j].ExternalIP
		})
	case "user":
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].Username > entries[j].Username
			}
			return entries[i].Username < entries[j].Username
		})
	case "command":
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].Command > entries[j].Command
			}
			return entries[i].Command < entries[j].Command
		})
	default: // time
		sort.Slice(entries, func(i, j int) bool {
			if reverse {
				return entries[i].Timestamp.After(entries[j].Timestamp)
			}
			return entries[i].Timestamp.Before(entries[j].Timestamp)
		})
	}
}

func outputEntries(entries []logging.LogEntry, correlator *logging.LogCorrelator, options *OutputOptions) {
	switch options.Format {
	case "json":
		outputJSONFormat(entries)
	case "csv":
		outputCSVFormat(entries)
	case "table":
		outputTableFormat(entries, options.Verbose)
	default:
		// Use correlator for text output to show command/output pairs
		if options.OutputJSON {
			executions := correlator.GetExecutions()
			data, _ := json.MarshalIndent(executions, "", "  ")
			fmt.Println(string(data))
		} else {
			for _, exec := range correlator.GetExecutions() {
				if options.Verbose {
					fmt.Println(formatExecutionVerbose(exec))
				} else {
					fmt.Println(logging.FormatExecution(exec))
				}
			}

			executions := correlator.GetExecutions()
			if len(executions) == 0 {
				fmt.Println("No matching command executions found.")
			} else {
				fmt.Printf("\nTotal executions: %d\n", len(executions))
			}
		}
	}
}

func outputJSONFormat(entries []logging.LogEntry) {
	data, _ := json.MarshalIndent(entries, "", "  ")
	fmt.Println(string(data))
}

func outputCSVFormat(entries []logging.LogEntry) {
	w := csv.NewWriter(os.Stdout)

	// Write header
	w.Write([]string{
		"Timestamp", "Type", "AgentID", "Hostname", "ExternalIP", "InternalIP",
		"Username", "OS", "Command", "CommandType", "CommandID", "SessionID",
		"Output", "Error",
	})

	for _, entry := range entries {
		w.Write([]string{
			entry.Timestamp.Format(time.RFC3339),
			entry.Type,
			entry.AgentID,
			entry.Hostname,
			entry.ExternalIP,
			entry.InternalIP,
			entry.Username,
			entry.OS,
			entry.Command,
			entry.CommandType,
			fmt.Sprintf("%v", entry.CommandID),
			entry.SessionID,
			truncateString(entry.Output, 100),
			entry.Error,
		})
	}

	w.Flush()
}

func outputTableFormat(entries []logging.LogEntry, verbose bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if verbose {
		fmt.Fprintln(w, "Time\tType\tAgent\tHost\tExtIP\tIntIP\tUser\tCommand\tSession")
		for _, entry := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				entry.Timestamp.Format("15:04:05"),
				entry.Type,
				truncateString(entry.AgentID, 8),
				entry.Hostname,
				entry.ExternalIP,
				entry.InternalIP,
				entry.Username,
				truncateString(entry.Command, 30),
				truncateString(entry.SessionID, 12),
			)
		}
	} else {
		fmt.Fprintln(w, "Time\tAgent\tHost\tUser\tCommand")
		for _, entry := range entries {
			if entry.Type == "command" || entry.Type == "output" {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					entry.Timestamp.Format("15:04:05"),
					truncateString(entry.AgentID, 8),
					entry.Hostname,
					entry.Username,
					truncateString(entry.Command, 40),
				)
			}
		}
	}

	w.Flush()
}

func formatExecutionVerbose(exec *logging.CommandExecution) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=== Command Execution ===\n"))
	sb.WriteString(fmt.Sprintf("Command ID: %v\n", exec.CommandID))
	sb.WriteString(fmt.Sprintf("Agent ID: %s\n", exec.AgentID))

	// Add enhanced fields if available (would need to update CommandExecution struct)
	sb.WriteString(fmt.Sprintf("User: %s\n", exec.Username))
	sb.WriteString(fmt.Sprintf("Command: %s\n", exec.Command))
	sb.WriteString(fmt.Sprintf("Sent: %s\n", exec.CommandTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Status: %s\n", exec.Status))

	if exec.OutputTime != nil {
		sb.WriteString(fmt.Sprintf("Output received: %s\n", exec.OutputTime.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Response time: %.3f seconds\n", exec.ResponseTime))
		sb.WriteString(fmt.Sprintf("Output size: %d bytes\n", exec.OutputSize))

		if exec.Output != "" {
			sb.WriteString("Output:\n")
			sb.WriteString(exec.Output)
			if !strings.HasSuffix(exec.Output, "\n") {
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

func showStatistics(correlator *logging.LogCorrelator, agentMap map[string]*AgentInfo) {
	stats := correlator.GetStats()

	fmt.Println("=== Command Execution Statistics ===")
	fmt.Printf("Total commands: %v\n", stats["total_commands"])
	fmt.Printf("Completed: %v\n", stats["completed_commands"])
	fmt.Printf("Pending: %v\n", stats["pending_commands"])
	fmt.Printf("Errors: %v\n", stats["error_commands"])

	if avgTime, ok := stats["avg_response_time"].(float64); ok && avgTime > 0 {
		fmt.Printf("Avg response time: %.3f seconds\n", avgTime)
		fmt.Printf("Min response time: %.3f seconds\n", stats["min_response_time"])
		fmt.Printf("Max response time: %.3f seconds\n", stats["max_response_time"])
	}

	fmt.Printf("\n=== Agent Statistics ===\n")
	fmt.Printf("Total unique agents: %d\n", len(agentMap))

	// Show top agents by command count
	agents := make([]*AgentInfo, 0, len(agentMap))
	for _, agent := range agentMap {
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].CommandCount > agents[j].CommandCount
	})

	fmt.Println("\nTop agents by command count:")
	for i, agent := range agents {
		if i >= 5 {
			break
		}
		fmt.Printf("  %s (%s) - %s: %d commands\n",
			truncateString(agent.AgentID, 8),
			agent.Hostname,
			agent.ExternalIP,
			agent.CommandCount,
		)
	}
}

func showAgentSummary(agentMap map[string]*AgentInfo) {
	fmt.Println("=== Agent Summary ===")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Agent\tHostname\tExternal IP\tInternal IP\tOS\tUser\tCommands\tSessions\tLast Seen")

	for _, agent := range agentMap {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			truncateString(agent.AgentID, 8),
			agent.Hostname,
			agent.ExternalIP,
			agent.InternalIP,
			agent.OS,
			agent.Username,
			agent.CommandCount,
			len(agent.Sessions),
			agent.LastSeen.Format("01/02 15:04"),
		)
	}

	w.Flush()
}

func followLog(logPath, agentFilter, hostFilter, ipFilter string) {
	fmt.Printf("Following log file: %s\n", logPath)
	if agentFilter != "" {
		fmt.Printf("Filtering by agent: %s\n", agentFilter)
	}
	if hostFilter != "" {
		fmt.Printf("Filtering by hostname: %s\n", hostFilter)
	}
	if ipFilter != "" {
		fmt.Printf("Filtering by IP: %s\n", ipFilter)
	}
	fmt.Println("Press Ctrl+C to stop...")
	fmt.Println(strings.Repeat("-", 80))

	// Keep track of what we've seen
	seenCommands := make(map[string]bool)

	for {
		entries, err := loadLogFile(logPath)
		if err != nil {
			log.Printf("Failed to load log file: %v", err)
			time.Sleep(1 * time.Second)
			continue
		}

		// Apply filters and create correlator
		correlator := logging.NewLogCorrelator()
		for _, entry := range entries {
			// Apply filters
			if agentFilter != "" && !strings.Contains(entry.AgentID, agentFilter) {
				continue
			}
			if hostFilter != "" && !strings.Contains(strings.ToLower(entry.Hostname), strings.ToLower(hostFilter)) {
				continue
			}
			if ipFilter != "" && !strings.Contains(entry.ExternalIP, ipFilter) && !strings.Contains(entry.InternalIP, ipFilter) {
				continue
			}

			correlator.ProcessEntry(entry)
		}

		// Display new executions
		for _, exec := range correlator.GetExecutions() {
			key := fmt.Sprintf("%s:%v", exec.AgentID, exec.CommandID)

			// Check if this is new or updated
			isNew := !seenCommands[key]
			wasIncomplete := seenCommands[key] && exec.Status == "completed"

			if isNew || wasIncomplete {
				if isNew {
					fmt.Printf("\n[NEW] ")
				} else {
					fmt.Printf("\n[COMPLETED] ")
				}

				// Enhanced one-line format with more context
				agentShort := exec.AgentID
				if len(agentShort) > 8 {
					agentShort = agentShort[:8]
				}

				// Try to get hostname from the entries (would need to enhance this)
				hostname := ""
				for _, entry := range entries {
					if entry.AgentID == exec.AgentID && entry.Hostname != "" {
						hostname = entry.Hostname
						break
					}
				}

				fmt.Printf("%s | %s@%s | Cmd: %v | %s",
					exec.CommandTime.Format("15:04:05"),
					agentShort,
					hostname,
					exec.CommandID,
					exec.Command)

				if exec.Status == "completed" && exec.Output != "" {
					output := strings.ReplaceAll(exec.Output, "\n", " ")
					if len(output) > 100 {
						output = output[:97] + "..."
					}
					fmt.Printf(" | Output: %s", output)
				} else if exec.Status == "sent" {
					fmt.Printf(" | Status: pending")
				}

				seenCommands[key] = true
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
