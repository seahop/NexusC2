# client/src/gui/widgets/terminal/terminal.py

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                            QTextEdit, QLineEdit, QPushButton, QTabWidget,
                            QTabBar, QApplication, QLabel)
from PyQt6.QtCore import Qt, pyqtSlot, QEvent
from PyQt6.QtGui import QTextCursor, QTextDocument
import os

# Import refactored components
from .command_history import CommandHistory
from .tab_completer import TabCompleter
from .command_buffer import CommandBuffer
from .handlers import CommandHandler, ResponseHandler

# Import external widgets (these stay in their original locations)
from ..logs import LogsWidget
from ..command_validator import CommandValidator
from ..upload import FileUploader
from ..virtual_terminal import VirtualTerminal
from ..bof_handler import BOFHandler
from ..inline_assembly_handler import InlineAssemblyHandler


class AgentTerminal(QWidget):
    def __init__(self, agent_name, agent_guid=None, ws_thread=None, agent_os=None):
        super().__init__()
        self.agent_name = agent_name
        self.agent_guid = agent_guid
        self.agent_os = agent_os  # Store the OS directly
        self.ws_thread = ws_thread
        
        print(f"DEBUG: Initializing AgentTerminal")
        print(f"DEBUG:   agent_name: {agent_name}")
        print(f"DEBUG:   agent_guid: {agent_guid}")
        print(f"DEBUG:   agent_os: {agent_os}")
        print(f"DEBUG:   ws_thread: {ws_thread}")
        
        # Initialize validators and utilities FIRST
        self.command_validator = CommandValidator(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "commands.toml")
        )
        
        # Initialize refactored components
        self.command_buffer = CommandBuffer()
        self.command_history = CommandHistory()
        self.tab_completer = TabCompleter(self.command_validator)
        
        # Set agent OS in tab completer
        if self.agent_os:
            self.tab_completer.set_agent_os(self.agent_os)
        
        self.completing = False
        
        # Initialize file uploader
        self.file_uploader = FileUploader(self)
        
        # Initialize BOF handler
        print(f"DEBUG: Initializing BOF handler with ws_thread: {ws_thread}")
        self.bof_handler = BOFHandler(ws_thread, self)
        print(f"DEBUG: BOF handler initialized: {self.bof_handler}")
        
        # Initialize Inline-Assembly handler
        print(f"DEBUG: Initializing Inline-Assembly handler with ws_thread: {ws_thread}")
        self.inline_assembly_handler = InlineAssemblyHandler(ws_thread, self)
        print(f"DEBUG: Inline-Assembly handler initialized: {self.inline_assembly_handler}")
        
        # Define command lists
        self.bof_commands = [
            'bof', 'bof-async', 'bof-jobs', 'bof-output', 
            'bof-kill', 'bof-load', 'bof-exec', 'bof-list', 
            'bof-unload'
        ]
        
        self.inline_assembly_commands = [
            'inline-assembly', 'inline-assembly-async',
            'inline-assembly-jobs', 'inline-assembly-output',
            'inline-assembly-kill', 'execute-assembly', 
            'inline-execute',
            'inline-assembly-jobs-clean',
            'inline-assembly-jobs-stats' 
        ]
        
        # Initialize handlers
        self.command_handler = CommandHandler(self)
        self.response_handler = ResponseHandler(self)
        
        # NOW apply global CNA scripts AFTER everything is initialized
        from ..cna_manager import CNAManager
        cna_manager = CNAManager()
        cna_manager.apply_to_terminal(self)
        
        # Setup UI
        self._setup_ui()
        
        # Connect signals
        self._connect_signals()
        
        self.is_initialized = False
        
        print(f"DEBUG: AgentTerminal initialization complete")

    def _setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout()

        # Search bar (initially hidden)
        self.search_widget = QWidget()
        search_layout = QHBoxLayout(self.search_widget)
        search_layout.setContentsMargins(0, 0, 0, 0)

        search_label = QLabel("Find:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search terminal output...")
        self.search_input.textChanged.connect(self.search_terminal)
        self.search_input.returnPressed.connect(self.find_next)
        self.search_input.setClearButtonEnabled(True)

        self.find_prev_button = QPushButton("◀ Previous")
        self.find_prev_button.clicked.connect(self.find_previous)
        self.find_next_button = QPushButton("Next ▶")
        self.find_next_button.clicked.connect(self.find_next)
        self.close_search_button = QPushButton("✕")
        self.close_search_button.clicked.connect(self.hide_search)

        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.find_prev_button)
        search_layout.addWidget(self.find_next_button)
        search_layout.addWidget(self.close_search_button)

        self.search_widget.setVisible(False)  # Hidden by default
        layout.addWidget(self.search_widget)

        # Terminal output area
        self.terminal_output = VirtualTerminal()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFontFamily("Monospace")
        self.terminal_output.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.terminal_output)
        
        # Command input area
        command_layout = QHBoxLayout()
        self.command_input = QLineEdit()
        self.command_input.returnPressed.connect(self.send_command)
        self.command_input.installEventFilter(self)
        
        self.send_button = QPushButton('Send')
        self.send_button.clicked.connect(self.send_command)
        
        command_layout.addWidget(self.command_input)
        command_layout.addWidget(self.send_button)
        layout.addLayout(command_layout)
        
        self.setLayout(layout)
    
    def _connect_signals(self):
        """Connect WebSocket signals to response handlers"""
        if self.ws_thread:
            print(f"DEBUG: Setting up WebSocket connections")
            
            # Set username if available
            if hasattr(self.ws_thread, 'username'):
                print(f"DEBUG: Setting username: {self.ws_thread.username}")
                self.command_buffer.set_username(self.ws_thread.username)
            
            # Connect response signals
            print(f"DEBUG: Connecting signal handlers")
            self.ws_thread.command_response.connect(self.response_handler.handle_command_output)
            self.ws_thread.command_result.connect(self.response_handler.handle_command_result)
            self.ws_thread.upload_response.connect(self.response_handler.handle_upload_response)
            
            # Connect BOF response handler
            if hasattr(self.ws_thread, 'bof_response'):
                self.ws_thread.bof_response.connect(self.response_handler.handle_bof_response)
                print(f"DEBUG:   bof_response connected")
            
            # Connect inline-assembly response handler
            if hasattr(self.ws_thread, 'inline_assembly_response'):
                self.ws_thread.inline_assembly_response.connect(
                    self.response_handler.handle_inline_assembly_response
                )
                print(f"DEBUG:   inline_assembly_response connected")
        else:
            print(f"DEBUG: No ws_thread provided - running in limited mode")
    
    def eventFilter(self, obj, event):
        """Event filter to handle Tab key for completion and arrow keys for history"""
        if obj == self.command_input and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            
            if key == Qt.Key.Key_Tab:
                self.handle_tab_completion()
                return True
            elif key == Qt.Key.Key_Up:
                # Navigate to previous command in history
                previous_cmd = self.command_history.get_previous(self.command_input.text())
                self.command_input.setText(previous_cmd)
                self.command_input.setCursorPosition(len(previous_cmd))
                self.completing = False
                self.tab_completer.reset()
                return True
            elif key == Qt.Key.Key_Down:
                # Navigate to next command in history
                next_cmd = self.command_history.get_next(self.command_input.text())
                self.command_input.setText(next_cmd)
                self.command_input.setCursorPosition(len(next_cmd))
                self.completing = False
                self.tab_completer.reset()
                return True
            elif key == Qt.Key.Key_Escape:
                # Cancel completion or clear input
                if self.completing:
                    self.command_input.setText(self.tab_completer.original_text)
                    self.completing = False
                    self.tab_completer.reset()
                else:
                    self.command_input.clear()
                    self.command_history.reset_position()
                return True
            else:
                # Any other key resets completion state and history navigation
                if self.completing and key not in [Qt.Key.Key_Shift, Qt.Key.Key_Control, Qt.Key.Key_Alt]:
                    self.completing = False
                    self.tab_completer.reset()
                # Reset history position when typing
                if key not in [Qt.Key.Key_Shift, Qt.Key.Key_Control, Qt.Key.Key_Alt, 
                              Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Home, Qt.Key.Key_End]:
                    self.command_history.reset_position()
        
        return super().eventFilter(obj, event)
    
    def handle_tab_completion(self):
        """Handle tab completion"""
        current_text = self.command_input.text()
        cursor_pos = self.command_input.cursorPosition()
        
        if not self.completing:
            # Start new completion
            completions, prefix, word_index = self.tab_completer.get_completions(current_text, cursor_pos)
            
            if not completions:
                return
            
            self.tab_completer.completion_candidates = completions
            self.tab_completer.completion_index = 0
            self.tab_completer.original_text = current_text
            self.tab_completer.completion_prefix = prefix
            self.completing = True
            
            # Apply first completion
            self.apply_completion(completions[0], word_index)
        else:
            # Cycle through completions
            self.tab_completer.completion_index = (
                self.tab_completer.completion_index + 1
            ) % len(self.tab_completer.completion_candidates)
            completion = self.tab_completer.completion_candidates[self.tab_completer.completion_index]
            
            # Determine word index
            parts = self.tab_completer.original_text.split()
            if self.tab_completer.original_text.endswith(' '):
                word_index = len(parts)
            else:
                word_index = len(parts) - 1
            
            self.apply_completion(completion, word_index)
    
    def apply_completion(self, completion, word_index):
        """Apply a completion to the input field"""
        current_text = self.command_input.text()
        parts = current_text.split()
        
        # Handle the case where we're adding a new word
        if word_index >= len(parts):
            parts.append(completion)
        else:
            parts[word_index] = completion
        
        # Reconstruct the command
        new_text = ' '.join(parts)
        
        # Add a space after completed commands (first word) but not after paths
        if word_index == 0 and not completion.endswith(os.sep):
            new_text += ' '
        
        self.command_input.setText(new_text)
        self.command_input.setCursorPosition(len(new_text))
    
    def send_command(self):
        """Send command using the command handler"""
        command = self.command_input.text()
        if not command:
            return

        # Add to history
        self.command_history.add_command(command)

        # Use command handler to process and send
        if self.command_handler.send_command(command):
            self.command_input.clear()

    def keyPressEvent(self, event):
        """Handle keyboard shortcuts"""
        # Ctrl+F to show search
        if event.key() == Qt.Key.Key_F and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.show_search()
            event.accept()
        else:
            super().keyPressEvent(event)

    def show_search(self):
        """Show the search bar and focus it"""
        self.search_widget.setVisible(True)
        self.search_input.setFocus()
        self.search_input.selectAll()

    def hide_search(self):
        """Hide the search bar and clear highlights"""
        self.search_widget.setVisible(False)
        self.search_input.clear()
        # Clear any highlights
        cursor = self.terminal_output.text_widget.textCursor()
        cursor.clearSelection()
        self.terminal_output.text_widget.setTextCursor(cursor)

    def search_terminal(self, search_text):
        """Search the terminal output and highlight first match"""
        if not search_text:
            # Clear highlights when search is empty
            cursor = self.terminal_output.text_widget.textCursor()
            cursor.clearSelection()
            self.terminal_output.text_widget.setTextCursor(cursor)
            return

        # Move cursor to start and search
        cursor = self.terminal_output.text_widget.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.terminal_output.text_widget.setTextCursor(cursor)

        # Find first occurrence
        self.terminal_output.text_widget.find(search_text)

    def find_next(self):
        """Find next occurrence of search text"""
        search_text = self.search_input.text()
        if not search_text:
            return

        # Search forward
        if not self.terminal_output.text_widget.find(search_text):
            # Not found forward, wrap to beginning
            cursor = self.terminal_output.text_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.terminal_output.text_widget.setTextCursor(cursor)
            self.terminal_output.text_widget.find(search_text)

    def find_previous(self):
        """Find previous occurrence of search text"""
        search_text = self.search_input.text()
        if not search_text:
            return

        # Search backward
        if not self.terminal_output.text_widget.find(search_text, QTextDocument.FindFlag.FindBackward):
            # Not found backward, wrap to end
            cursor = self.terminal_output.text_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.terminal_output.text_widget.setTextCursor(cursor)
            self.terminal_output.text_widget.find(search_text, QTextDocument.FindFlag.FindBackward)

    def update_display(self, incremental=False):
        """Update the terminal display with current buffer content

        Args:
            incremental: If True, only append new content instead of full redraw
        """
        print(f"AgentTerminal [{self.agent_name}]: Updating terminal display")

        # Check if we're at bottom before updating
        scrollbar = self.terminal_output.verticalScrollBar()
        was_at_bottom = scrollbar.value() >= scrollbar.maximum() - 50

        if incremental and hasattr(self, '_last_output_count'):
            # Incremental update: only append new content
            current_count = len(self.command_buffer.received_outputs)
            if current_count > self._last_output_count:
                # Get only new outputs
                new_outputs = list(self.command_buffer.received_outputs)[self._last_output_count:]
                new_lines = [output.get('output', '') for output in new_outputs if output.get('output')]

                if new_lines:
                    # Append only new content without clearing
                    new_content = "\n".join(new_lines)
                    self.terminal_output.append(new_content)

                self._last_output_count = current_count
        else:
            # Full update (used for initial load or when incremental not possible)
            display_content = self.command_buffer.get_display_content()

            if was_at_bottom:
                # If we were at bottom, use append to maintain auto-scroll
                self.terminal_output.setText("")  # Clear first
                self.terminal_output.append(display_content)
            else:
                # If we weren't at bottom, use setText to maintain position
                self.terminal_output.setText(display_content)

            # Track output count for incremental updates
            self._last_output_count = len(self.command_buffer.received_outputs)
    
    def initialize_with_history(self, commands, outputs_by_command):
        """Initialize terminal with command history - optimized for single render"""
        print(f"DEBUG: Initializing history for agent {self.agent_name}")
        if self.is_initialized:
            print("DEBUG: Already initialized, skipping")
            return

        try:
            # Sort commands chronologically
            sorted_commands = sorted(commands, key=lambda x: x[4])
            print(f"DEBUG: Processing {len(sorted_commands)} commands")

            # Buffer all outputs without rendering
            for command in sorted_commands:
                command_id, username, agent_guid, command_text, timestamp = command

                if agent_guid == self.agent_guid:
                    # Add command to history (for navigation)
                    self.command_history.add_command(command_text)

                    # Add command to buffer
                    formatted_command = {
                        "timestamp": timestamp,
                        "output": f"[{timestamp}] {username} > {command_text}"
                    }
                    self.command_buffer.add_output(formatted_command)

                    # Add corresponding outputs
                    command_outputs = outputs_by_command.get(command_id, [])
                    for output in command_outputs:
                        output_id, cmd_id, output_text, output_timestamp = output
                        formatted_output = {
                            "timestamp": output_timestamp,
                            "output": output_text
                        }
                        self.command_buffer.add_output(formatted_output)

            # Single render at the end - much more efficient
            print(f"DEBUG: Rendering {len(self.command_buffer.received_outputs)} outputs")
            self.update_display()
            self.is_initialized = True

            print(f"DEBUG: History initialization complete for {self.agent_name}")

        except Exception as e:
            print(f"ERROR in initialize_with_history: {e}")
            import traceback
            traceback.print_exc()
            
class TerminalWidget(QWidget):
    """Main widget that manages terminal tabs"""
    
    def __init__(self, ws_thread=None):
        super().__init__()
        self.ws_thread = ws_thread
        self.command_history = {"commands": [], "outputs": []}
        self.outputs_by_command = {}
        self.agent_tree = None
        self.agent_aliases = {}  # Track agent renames (agent_guid -> display_name)

        layout = QVBoxLayout()

        # Connect signals if WebSocket thread is available
        if ws_thread:
            ws_thread.command_response.connect(self.handle_command_output)
            ws_thread.command_result.connect(self.handle_command_result)

            if hasattr(ws_thread, 'bof_response'):
                ws_thread.bof_response.connect(self.handle_bof_response)

            if hasattr(ws_thread, 'inline_assembly_response'):
                ws_thread.inline_assembly_response.connect(self.handle_inline_assembly_response)
        
        # Setup tabs
        self.tabs = QTabWidget()
        self.tabs.tabCloseRequested.connect(self.close_tab)
        
        # Create general terminal and logs tabs
        self.general_terminal = AgentTerminal("General", ws_thread=self.ws_thread)
        self.tabs.addTab(self.general_terminal, "Terminal")
        
        self.logs = LogsWidget()
        self.tabs.addTab(self.logs, "Logs")
        
        # Make tabs closable but protect Terminal and Logs tabs
        self.tabs.setTabsClosable(True)
        self.tabs.tabBar().setTabButton(0, QTabBar.ButtonPosition.RightSide, None)
        self.tabs.tabBar().setTabButton(1, QTabBar.ButtonPosition.RightSide, None)
        
        layout.addWidget(self.tabs)
        self.setLayout(layout)
        
        self.agent_terminals = {}
        self.log_message("C2 Client started")
    
    def store_command_history(self, commands, outputs_by_command):
        """Store command history for later use when terminals are created"""
        self.command_history = commands
        self.outputs_by_command = outputs_by_command
        print(f"TerminalWidget: Stored {len(commands)} commands in history")
    
    def add_agent_tab(self, agent_name, agent_guid=None):
        """Create or activate an agent terminal tab"""
        # Check if agent has been renamed
        display_name = self.agent_aliases.get(agent_guid, agent_name)

        # Check if terminal already exists (even if tab was closed)
        if agent_guid in self.agent_terminals:
            # Terminal exists - check if it's already in a tab
            existing_terminal = self.agent_terminals[agent_guid]
            tab_exists = False

            for i in range(self.tabs.count()):
                if self.tabs.widget(i) == existing_terminal:
                    # Tab already open, just switch to it
                    self.tabs.setCurrentIndex(i)
                    tab_exists = True
                    break

            if not tab_exists:
                # Terminal exists but tab was closed - re-add the tab
                print(f"TerminalWidget: Reopening existing terminal for {display_name} (restoring history)")
                # Use display_name (which could be the alias) instead of agent_name
                index = self.tabs.addTab(existing_terminal, f"Agent: {display_name}")
                self.tabs.setCurrentIndex(index)
        else:
            # Create new terminal
            print(f"TerminalWidget: Creating new tab for agent_name: {agent_name}, agent_guid: {agent_guid}")

            # Get agent OS from agent tree
            agent_os = None
            if self.agent_tree:
                agent = self.agent_tree.get_agent_by_guid(agent_guid)
                if agent:
                    # First try to get OS from dedicated field
                    agent_os = agent.get('os', None)

                    # Fallback to extracting from details if not found
                    if not agent_os:
                        for detail in agent.get('details', []):
                            if detail.startswith('OS:'):
                                agent_os = detail.replace('OS:', '').strip()
                                break

                    print(f"TerminalWidget: Agent OS detected as: {agent_os}")

            # Pass OS to AgentTerminal
            agent_terminal = AgentTerminal(agent_name, agent_guid, self.ws_thread, agent_os)
            self.agent_terminals[agent_guid] = agent_terminal
            # Use display_name (which could be the alias) instead of agent_name
            index = self.tabs.addTab(agent_terminal, f"Agent: {display_name}")

            # Initialize with any stored command history for this agent
            if hasattr(self, 'command_history'):
                agent_commands = [cmd for cmd in self.command_history if cmd[2] == agent_guid]
                for command in agent_commands:
                    command_id = command[0]
                    username = command[1]
                    command_text = command[3]
                    timestamp = command[4]

                    # Add command to terminal's history for navigation
                    agent_terminal.command_history.add_command(command_text)

                    # Add command to buffer
                    formatted_command = {
                        "timestamp": timestamp,
                        "output": f"[{timestamp}] {username} > {command_text}"
                    }
                    agent_terminal.command_buffer.add_output(formatted_command)

                    # Add corresponding outputs
                    command_outputs = self.outputs_by_command.get(command_id, [])
                    for output in command_outputs:
                        formatted_output = {
                            "timestamp": output[3],
                            "output": output[2]
                        }
                        agent_terminal.command_buffer.add_output(formatted_output)

                agent_terminal.update_display()

            self.tabs.setCurrentIndex(index)

    def handle_agent_renamed(self, data):
        """Handle agent rename notification and update tab title"""
        agent_id = data.get('agent_id')
        new_name = data.get('new_name')

        # Update local alias cache
        self.agent_aliases[agent_id] = new_name

        # Update tab title if the terminal is currently open in a tab
        if agent_id in self.agent_terminals:
            terminal = self.agent_terminals[agent_id]

            # Find the tab with this terminal
            for i in range(self.tabs.count()):
                if self.tabs.widget(i) == terminal:
                    # Update the tab title with the new name
                    self.tabs.setTabText(i, f"Agent: {new_name}")
                    self.log_message(f"Agent {agent_id[:8]} renamed to '{new_name}'")
                    break

    def close_tab(self, index):
        """Close a terminal tab (hides it but preserves history)"""
        widget = self.tabs.widget(index)

        # Don't close Terminal or Logs tabs
        if widget == self.general_terminal or widget == self.logs:
            return

        # Handle agent terminals - just remove from tabs but keep in memory
        agent_guid = None
        agent_name = None
        for guid, terminal in self.agent_terminals.items():
            if terminal == widget:
                agent_guid = guid
                agent_name = terminal.agent_name
                break

        if agent_guid:
            # Remove from tabs but DON'T delete from agent_terminals
            # This preserves command history when the tab is reopened
            self.tabs.removeTab(index)
            self.log_message(f"Closed terminal for {agent_name} (history preserved)")
        else:
            # Handle other closeable tabs
            self.tabs.removeTab(index)
    
    def log_message(self, message):
        """Add a message to the logs"""
        self.logs.add_log(message)
    
    def set_ws_thread(self, ws_thread):
        """Update WebSocket thread for all terminals"""
        self.ws_thread = ws_thread
        self.general_terminal.ws_thread = ws_thread
        for terminal in self.agent_terminals.values():
            terminal.ws_thread = ws_thread
    
    @pyqtSlot(dict)
    def handle_command_response(self, response_data):
        """Route command responses to appropriate terminal"""
        print(f"TerminalWidget: Received command_response: {response_data}")
        
        data = response_data.get('data', {})
        agent_id = data.get('agent_id')
        
        print(f"TerminalWidget: Routing output to agent_id: {agent_id}")
        
        if agent_id in self.agent_terminals:
            print(f"TerminalWidget: Found terminal for agent_id {agent_id}")
            self.agent_terminals[agent_id].response_handler.handle_command_output(response_data)
        else:
            print(f"TerminalWidget: No terminal found for agent_id {agent_id}. Logging to General Terminal.")
            self.general_terminal.response_handler.handle_command_output(response_data)
    
    @pyqtSlot(dict)
    def handle_command_result(self, result_data):
        """Route command results to the appropriate terminal"""
        print(f"TerminalWidget: Handling command result: {result_data}")
        agent_id = result_data.get('agent_id')
        
        if agent_id in self.agent_terminals:
            terminal = self.agent_terminals[agent_id]
            print(f"TerminalWidget: Routing result to terminal for agent_id {agent_id}")
            terminal.response_handler.handle_command_result(result_data)
        else:
            print(f"TerminalWidget: No terminal found for agent {agent_id}. Logging to general terminal.")
            self.general_terminal.response_handler.handle_command_result(result_data)
    
    @pyqtSlot(dict)
    def handle_bof_response(self, response_data):
        """Route BOF responses to the appropriate terminal"""
        print(f"TerminalWidget: Handling BOF response: {response_data}")
        
        # Extract agent_id from response data
        agent_id = None
        if 'data' in response_data:
            agent_id = response_data['data'].get('agent_id')
        elif 'agent_id' in response_data:
            agent_id = response_data.get('agent_id')
        
        if agent_id and agent_id in self.agent_terminals:
            terminal = self.agent_terminals[agent_id]
            print(f"TerminalWidget: Routing BOF response to terminal for agent_id {agent_id}")
            terminal.response_handler.handle_bof_response(response_data)
        else:
            print(f"TerminalWidget: No terminal found for agent {agent_id}. Logging to general terminal.")
            self.general_terminal.response_handler.handle_bof_response(response_data)
    
    @pyqtSlot(dict)
    def handle_inline_assembly_response(self, response_data):
        """Route inline-assembly responses to the appropriate terminal"""
        print(f"TerminalWidget: Handling inline-assembly response: {response_data}")
        
        # Extract agent_id from response data
        agent_id = None
        if 'data' in response_data:
            agent_id = response_data['data'].get('agent_id')
        elif 'agent_id' in response_data:
            agent_id = response_data.get('agent_id')
        
        if agent_id and agent_id in self.agent_terminals:
            terminal = self.agent_terminals[agent_id]
            print(f"TerminalWidget: Routing inline-assembly response to terminal for agent_id {agent_id}")
            terminal.response_handler.handle_inline_assembly_response(response_data)
        else:
            print(f"TerminalWidget: No terminal found for agent {agent_id}. Logging to general terminal.")
            self.general_terminal.response_handler.handle_inline_assembly_response(response_data)
    
    # Delegation methods for signal handling
    def handle_command_output(self, output_data):
        """Delegate to handle_command_response for consistency"""
        self.handle_command_response(output_data)