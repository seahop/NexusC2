# client/src/gui/widgets/cna_debug_console.py

from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, 
                            QPushButton, QSplitter, QLabel, QCheckBox,
                            QComboBox, QGroupBox, QLineEdit)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import (QTextCharFormat , QTextCursor, QColor, QTextCharFormat, QFont)
from datetime import datetime

class CNADebugConsole(QDialog):
    """
    Debug console for CNA script loading and execution
    Shows detailed parsing info, errors, and execution traces
    """
    
    # Signal to request script reload
    reload_requested = pyqtSignal(str)
    
    def __init__(self, parent=None, cna_interpreter=None):
        super().__init__(parent)
        self.cna_interpreter = cna_interpreter
        self.setWindowTitle("CNA Script Debug Console")
        self.setGeometry(200, 200, 1000, 700)
        
        # Debug settings
        self.verbose_mode = True
        self.show_parsing = True
        self.show_execution = True
        self.show_file_search = True
        self.log_entries = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the debug console UI"""
        main_layout = QVBoxLayout()
        
        # Header with controls
        header_layout = QHBoxLayout()
        
        # Debug level controls
        debug_group = QGroupBox("Debug Options")
        debug_layout = QHBoxLayout()
        
        self.verbose_check = QCheckBox("Verbose")
        self.verbose_check.setChecked(self.verbose_mode)
        self.verbose_check.toggled.connect(self.toggle_verbose)
        debug_layout.addWidget(self.verbose_check)
        
        self.parsing_check = QCheckBox("Show Parsing")
        self.parsing_check.setChecked(self.show_parsing)
        self.parsing_check.toggled.connect(self.toggle_parsing)
        debug_layout.addWidget(self.parsing_check)
        
        self.execution_check = QCheckBox("Show Execution")
        self.execution_check.setChecked(self.show_execution)
        self.execution_check.toggled.connect(self.toggle_execution)
        debug_layout.addWidget(self.execution_check)
        
        self.file_search_check = QCheckBox("Show File Search")
        self.file_search_check.setChecked(self.show_file_search)
        self.file_search_check.toggled.connect(self.toggle_file_search)
        debug_layout.addWidget(self.file_search_check)
        
        debug_group.setLayout(debug_layout)
        header_layout.addWidget(debug_group)
        
        # Filter controls
        filter_group = QGroupBox("Filter")
        filter_layout = QHBoxLayout()
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All", "Errors", "Warnings", "Info", "Debug"])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(QLabel("Level:"))
        filter_layout.addWidget(self.filter_combo)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search logs...")
        self.search_input.textChanged.connect(self.search_logs)
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.search_input)
        
        filter_group.setLayout(filter_layout)
        header_layout.addWidget(filter_group)
        
        header_layout.addStretch()
        
        # Action buttons
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_console)
        header_layout.addWidget(clear_button)
        
        export_button = QPushButton("Export Logs")
        export_button.clicked.connect(self.export_logs)
        header_layout.addWidget(export_button)
        
        main_layout.addLayout(header_layout)
        
        # Splitter for main content
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Debug output console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Monospace", 9))
        self.console.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #333;
            }
        """)
        
        # Status summary panel
        self.status_panel = QTextEdit()
        self.status_panel.setReadOnly(True)
        self.status_panel.setMaximumHeight(150)
        self.status_panel.setFont(QFont("Monospace", 9))
        self.status_panel.setStyleSheet("""
            QTextEdit {
                background-color: #252525;
                color: #d4d4d4;
                border: 1px solid #333;
            }
        """)
        
        splitter.addWidget(self.console)
        splitter.addWidget(self.status_panel)
        splitter.setSizes([500, 150])
        
        main_layout.addWidget(splitter)
        
        # Bottom button bar
        button_layout = QHBoxLayout()
        
        refresh_button = QPushButton("Refresh Status")
        refresh_button.clicked.connect(self.refresh_status)
        button_layout.addWidget(refresh_button)
        
        validate_button = QPushButton("Validate Scripts")
        validate_button.clicked.connect(self.validate_scripts)
        button_layout.addWidget(validate_button)
        
        button_layout.addStretch()
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)
        
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)
        
        # Initial status update
        self.refresh_status()
    
    def log(self, level: str, category: str, message: str, details: dict = None):
        """Add a log entry to the console"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Store log entry
        entry = {
            'timestamp': timestamp,
            'level': level,
            'category': category,
            'message': message,
            'details': details or {}
        }
        self.log_entries.append(entry)
        
        # Format the message
        if level == "ERROR":
            color = "#ff6b6b"
            prefix = "[-]"
        elif level == "WARNING":
            color = "#ffd93d"
            prefix = "[!]"
        elif level == "INFO":
            color = "#6bcf7f"
            prefix = "[+]"
        elif level == "DEBUG":
            color = "#9ca3af"
            prefix = "[*]"
        else:
            color = "#d4d4d4"
            prefix = "[.]"
        
        # Build the formatted message
        formatted = f'<span style="color: #888">{timestamp}</span> '
        formatted += f'<span style="color: {color}">{prefix}</span> '
        formatted += f'<span style="color: #4dabf7">[{category}]</span> '
        formatted += f'<span style="color: {color}">{message}</span>'
        
        # Add details if verbose mode
        if details and self.verbose_mode:
            for key, value in details.items():
                formatted += f'<br>&nbsp;&nbsp;&nbsp;&nbsp;<span style="color: #888">{key}:</span> '
                formatted += f'<span style="color: #9ca3af">{value}</span>'
        
        # Append to console
        self.console.append(formatted)
        
        # Auto-scroll to bottom
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.console.setTextCursor(cursor)
    
    def log_script_load(self, script_path: str, success: bool, error: str = None):
        """Log script loading attempt"""
        if success:
            self.log("INFO", "LOADER", f"Successfully loaded script: {script_path}")
        else:
            self.log("ERROR", "LOADER", f"Failed to load script: {script_path}", 
                    {"error": error or "Unknown error"})
    
    def log_command_registration(self, cmd_name: str, description: str):
        """Log command registration"""
        if self.show_parsing:
            self.log("DEBUG", "PARSER", f"Registered command: {cmd_name}",
                    {"description": description[:50] + "..." if len(description) > 50 else description})
    
    def log_alias_registration(self, alias_name: str, bof_name: str = None):
        """Log alias registration"""
        if self.show_parsing:
            details = {}
            if bof_name:
                details["bof"] = bof_name
            self.log("DEBUG", "PARSER", f"Registered alias: {alias_name}", details)
    
    def log_bof_search(self, bof_name: str, search_paths: list, found_path: str = None):
        """Log BOF file search"""
        if self.show_file_search:
            if found_path:
                self.log("INFO", "BOF_SEARCH", f"Found BOF '{bof_name}' at: {found_path}")
            else:
                self.log("WARNING", "BOF_SEARCH", f"BOF '{bof_name}' not found",
                        {"searched": ", ".join(search_paths[:3]) + "..." if len(search_paths) > 3 else ", ".join(search_paths)})
    
    def log_command_execution(self, command: str, args: list, success: bool = None):
        """Log command execution"""
        if self.show_execution:
            level = "INFO" if success else "ERROR" if success is False else "DEBUG"
            self.log(level, "EXEC", f"Executing command: {command}",
                    {"args": str(args)} if args else None)
    
    def log_parse_error(self, error: str, line_num: int = None, line_content: str = None):
        """Log parsing error"""
        details = {}
        if line_num:
            details["line"] = line_num
        if line_content:
            details["content"] = line_content[:100] + "..." if len(line_content) > 100 else line_content
        
        self.log("ERROR", "PARSER", error, details)
    
    def refresh_status(self):
        """Refresh the status panel with current CNA interpreter state"""
        if not self.cna_interpreter:
            self.status_panel.setText("No CNA interpreter attached")
            return
        
        status = []
        status.append("=== CNA Interpreter Status ===\n")
        
        # Loaded scripts
        status.append(f"Loaded Scripts: {len(self.cna_interpreter.loaded_scripts)}")
        for script in self.cna_interpreter.loaded_scripts:
            status.append(f"  • {script}")
        
        # Registered commands
        status.append(f"\nRegistered Commands: {len(self.cna_interpreter.commands)}")
        if len(self.cna_interpreter.commands) <= 10:
            for cmd in sorted(self.cna_interpreter.commands.keys()):
                status.append(f"  • {cmd}")
        else:
            # Show first 5 and last 5 if too many
            sorted_cmds = sorted(self.cna_interpreter.commands.keys())
            for cmd in sorted_cmds[:5]:
                status.append(f"  • {cmd}")
            status.append("  ...")
            for cmd in sorted_cmds[-5:]:
                status.append(f"  • {cmd}")
        
        # Registered aliases
        status.append(f"\nRegistered Aliases: {len(self.cna_interpreter.aliases)}")
        
        # BOF mappings
        bof_count = sum(1 for alias in self.cna_interpreter.aliases.values() if alias.bof_name)
        status.append(f"BOF Mappings: {bof_count}")
        
        self.status_panel.setText("\n".join(status))
    
    def validate_scripts(self):
        """Validate loaded scripts and check for issues"""
        if not self.cna_interpreter:
            self.log("ERROR", "VALIDATOR", "No CNA interpreter attached")
            return
        
        self.log("INFO", "VALIDATOR", "Starting script validation...")
        
        issues = 0
        
        # Check each alias
        for alias_name, alias in self.cna_interpreter.aliases.items():
            if alias.bof_name:
                # Try to find the BOF file
                bof_path = self.cna_interpreter._find_bof_file(alias.bof_name)
                if not bof_path:
                    self.log("WARNING", "VALIDATOR", 
                            f"BOF file not found for alias '{alias_name}'",
                            {"bof_name": alias.bof_name})
                    issues += 1
                else:
                    self.log("DEBUG", "VALIDATOR",
                            f"BOF file found for alias '{alias_name}'",
                            {"path": bof_path})
        
        # Check command-to-alias mappings
        for cmd_name, cmd in self.cna_interpreter.commands.items():
            if cmd_name not in self.cna_interpreter.aliases:
                self.log("WARNING", "VALIDATOR",
                        f"Command '{cmd_name}' has no corresponding alias",
                        {"handler": cmd.handler})
                issues += 1
        
        # Summary
        if issues == 0:
            self.log("INFO", "VALIDATOR", "Validation completed - no issues found")
        else:
            self.log("WARNING", "VALIDATOR", f"Validation completed - {issues} issue(s) found")
    
    def clear_console(self):
        """Clear the debug console"""
        self.console.clear()
        self.log_entries.clear()
        self.log("INFO", "CONSOLE", "Console cleared")
    
    def export_logs(self):
        """Export logs to file"""
        from PyQt6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Debug Logs",
            f"cna_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    for entry in self.log_entries:
                        f.write(f"[{entry['timestamp']}] [{entry['level']}] [{entry['category']}] {entry['message']}\n")
                        if entry['details']:
                            for key, value in entry['details'].items():
                                f.write(f"    {key}: {value}\n")
                
                self.log("INFO", "EXPORT", f"Logs exported to: {file_path}")
            except Exception as e:
                self.log("ERROR", "EXPORT", f"Failed to export logs: {str(e)}")
    
    def apply_filter(self, filter_level: str):
        """Filter console output by log level"""
        # This would require reimplementing the log display
        # For now, just log the action
        self.log("INFO", "FILTER", f"Filter set to: {filter_level}")
    
    def search_logs(self, search_text: str):
        """Search through logs"""
        if not search_text:
            return
        
        # Highlight matching text in console
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        
        # Clear previous highlights
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.setCharFormat(QTextCharFormat())
        
        # Search and highlight
        while self.console.find(search_text):
            cursor = self.console.textCursor()
            format = QTextCharFormat()
            format.setBackground(QColor("#3a3a00"))
            cursor.setCharFormat(format)
    
    def toggle_verbose(self, checked: bool):
        """Toggle verbose mode"""
        self.verbose_mode = checked
        self.log("INFO", "SETTINGS", f"Verbose mode: {'ON' if checked else 'OFF'}")
    
    def toggle_parsing(self, checked: bool):
        """Toggle parsing logs"""
        self.show_parsing = checked
        self.log("INFO", "SETTINGS", f"Show parsing: {'ON' if checked else 'OFF'}")
    
    def toggle_execution(self, checked: bool):
        """Toggle execution logs"""
        self.show_execution = checked
        self.log("INFO", "SETTINGS", f"Show execution: {'ON' if checked else 'OFF'}")
    
    def toggle_file_search(self, checked: bool):
        """Toggle file search logs"""
        self.show_file_search = checked
        self.log("INFO", "SETTINGS", f"Show file search: {'ON' if checked else 'OFF'}")