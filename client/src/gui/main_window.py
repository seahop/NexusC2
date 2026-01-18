#main_window.py
from PyQt6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QDialog,
                            QMenu, QSplitter, QMessageBox, QFileDialog, QApplication,
                            QListWidget, QListWidgetItem, QPushButton, QHBoxLayout, QLabel, QComboBox, QVBoxLayout)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QMetaObject, Q_ARG, pyqtSlot, QTimer
from PyQt6.QtGui import QPalette, QColor, QIcon

from .dialogs import ServerConnectDialog, CreateListenerDialog, CreatePayloadDialog, SettingsDialog, VersionDialog
from .widgets import AgentTreeWidget, TerminalWidget, AgentDisplayWidget
from utils.database import StateDatabase
from .widgets.downloads import DownloadsWidget
from .widgets.listeners import ListenersWidget
from .widgets.floating_status_indicator import FloatingStatusIndicator
from .widgets.notifications import NotificationManager
import json
import os
import base64
from pathlib import Path

class C2ClientGUI(QMainWindow):
    state_loaded = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.config_dir = Path.home() / '.nexus'
        self.config_dir.mkdir(exist_ok=True)
        self.window_state_file = self.config_dir / 'window_state.json'

        # Load application settings
        self.app_settings = self._load_app_settings()

        self.initUI()
        self.ws_thread = None
        self.is_connected = False
        self.ws_client = None
        self.processed_listener_ids = set()
        self.state_db = StateDatabase()
        if self.ws_client:
            self.ws_client.agent_tree_widget = self.agent_tree

        # Initialize notification manager
        self.notification_manager = NotificationManager(self)
        self.notification_manager.notification_clicked.connect(self.on_notification_clicked)

        # Initialize CNA Manager with database for persistence
        self._init_cna_manager()

        # Restore window geometry after UI is set up
        self.restore_window_state()

        # Flag to track if initial view has been applied
        self._initial_view_applied = False

    def _load_app_settings(self):
        """Load application settings from config file."""
        config_file = self.config_dir / 'settings.json'
        defaults = {
            'theme': 'Dark',
            'default_view': 1,  # Default to Table view
            'guid_display_length': 16,
            'notifications_enabled': True,
            'notification_sound_enabled': True,
            'notification_sound_volume': 70,
        }
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    saved = json.load(f)
                    for key, value in defaults.items():
                        if key not in saved:
                            saved[key] = value
                    return saved
            except:
                pass
        return defaults

    def _init_cna_manager(self):
        """Initialize CNA Manager with database and load persisted scripts"""
        from .widgets.cna_manager import CNAManager

        self.cna_manager = CNAManager()
        self.cna_manager.set_database(self.state_db)

        # Load persisted CNA scripts
        result = self.cna_manager.load_persisted_scripts()

        # If there were failures, show notification after UI is ready
        if result['failed']:
            # Use QTimer to show message after event loop starts
            QTimer.singleShot(500, lambda: self._show_cna_startup_errors(result['failed']))

    def _show_cna_startup_errors(self, failed_scripts):
        """Show notification about CNA scripts that failed to load on startup"""
        count = len(failed_scripts)
        log_path = self.cna_manager.get_log_path()

        msg = f"{count} CNA script(s) failed to load on startup.\n\n"
        for item in failed_scripts[:3]:  # Show first 3
            msg += f"- {os.path.basename(item['path'])}\n"
            msg += f"  Error: {item['error'][:50]}...\n" if len(item['error']) > 50 else f"  Error: {item['error']}\n"
        if count > 3:
            msg += f"\n...and {count - 3} more.\n"
        msg += f"\nFull details logged to:\n{log_path}\n\n"
        msg += "You can manage these scripts via Tools > Manage CNA Scripts."

        QMessageBox.warning(self, "CNA Script Load Errors", msg)

    def _apply_default_view(self):
        """Apply the default view setting on startup.

        Uses saved preference from window_state.json if available,
        otherwise falls back to default_view from settings.json.
        """
        # Check for saved preference in window_state.json first
        saved_view = None
        try:
            if self.window_state_file.exists():
                with open(self.window_state_file, 'r') as f:
                    state = json.load(f)
                    if 'current_view_id' in state:
                        saved_view = state['current_view_id']
        except Exception:
            pass

        # Use saved preference if available, otherwise use settings default
        if saved_view is not None:
            view_to_apply = saved_view
        else:
            # No saved preference - use default_view from settings (default to Table = 1)
            view_to_apply = self.app_settings.get('default_view', 1)

        if hasattr(self, 'agent_display'):
            # Use _set_initial_view to avoid triggering a save
            self.agent_display._set_initial_view(view_to_apply)
            # Manually trigger the view changed handler to set splitter orientation
            self.on_agent_view_changed(view_to_apply)
            # Refresh the table if that's the view being shown
            if view_to_apply == 1 and hasattr(self.agent_display, 'table_widget'):
                self.agent_display.table_widget.refresh_from_tree()

    def on_notification_clicked(self, agent_guid):
        """Handle notification click - focus on the agent."""
        if hasattr(self, 'agent_tree') and agent_guid:
            agent = self.agent_tree.agent_by_guid.get(agent_guid)
            if agent:
                # Open terminal for the agent
                self.terminal.add_agent_tab(agent['name'], agent_guid)
                # Bring window to front
                self.activateWindow()
                self.raise_()

    def initUI(self):
        self.setWindowTitle('Nexus')
        self.setGeometry(100, 100, 1600, 950)

        # Set window icon (smaller n.png for title bar)
        icon_path = Path(__file__).parent / 'resources' / 'n.png'
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
        
        # Apply additional window-specific attributes for Linux
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        
        # Set window-specific palette (reinforces application-level palette)
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        self.setPalette(palette)
        
        self.is_connected = False 
        self.ws_client = None
        self.updateMenuState()

        self.setupMenuBar()
        self.setupMainWidget()
        self.terminal_widget = self.terminal 
        self.load_and_apply_theme()

    def update_window_decorations(self, is_dark_theme=True):
        """
        Update window decorations (title bar, borders) to match the theme.
        This method updates both the window palette and the application palette
        to ensure Linux window managers respect the theme change.
        """
        
        palette = QPalette()
        
        if is_dark_theme:
            # Dark theme colors
            palette.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
        else:
            # Light theme colors
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(255, 255, 220))
            palette.setColor(QPalette.ColorRole.ToolTipText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(0, 0, 255))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 120, 212))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        # Update BOTH window palette and application palette
        # This is crucial for Linux window managers to update decorations
        self.setPalette(palette)
        QApplication.instance().setPalette(palette)
        
        print(f"Window decorations updated to {'dark' if is_dark_theme else 'light'} theme")

    def setupMenuBar(self):
        from PyQt6.QtGui import QKeySequence

        menubar = self.menuBar()

        # Server menu
        serverMenu = menubar.addMenu('Server')
        connectAction = serverMenu.addAction('Connect...')
        connectAction.setShortcut(QKeySequence('Ctrl+Shift+C'))
        connectAction.triggered.connect(self.showConnectDialog)
        disconnectAction = serverMenu.addAction('Disconnect')
        disconnectAction.triggered.connect(self.disconnectFromServer)

        self.updateMenuState()

        # View menu
        viewMenu = menubar.addMenu('View')
        showListenersAction = viewMenu.addAction('Listeners')
        showListenersAction.setShortcut(QKeySequence('Ctrl+L'))
        showListenersAction.triggered.connect(self.showListeners)
        showDownloadsAction = viewMenu.addAction('Downloads')
        showDownloadsAction.setShortcut(QKeySequence('Ctrl+D'))
        showDownloadsAction.triggered.connect(self.showDownloads)

        # Tools menu
        toolsMenu = menubar.addMenu('Tools')
        createListenerAction = toolsMenu.addAction('Create Listener')
        createListenerAction.setShortcut(QKeySequence('Ctrl+Shift+L'))
        createListenerAction.triggered.connect(self.showCreateListener)

        createPayloadAction = toolsMenu.addAction('Create Payload')
        createPayloadAction.setShortcut(QKeySequence('Ctrl+P'))
        createPayloadAction.triggered.connect(self.showCreatePayload)
        
        # Add CNA script loading option
        toolsMenu.addSeparator()
        loadCNAAction = toolsMenu.addAction('Load CNA Script...')
        loadCNAAction.triggered.connect(self.loadCNAScript)
        manageCNAAction = toolsMenu.addAction('Manage CNA Scripts...')
        manageCNAAction.triggered.connect(self.manageCNAScripts)
        cnaDebugAction = toolsMenu.addAction('CNA Debug Console...')
        cnaDebugAction.triggered.connect(self.showCNADebugConsole)


        optionsMenu = menubar.addMenu('Options')
        settingsAction = optionsMenu.addAction('Settings...')
        settingsAction.setShortcut(QKeySequence('Ctrl+,'))
        settingsAction.triggered.connect(self.showSettings)
        versionAction = optionsMenu.addAction('Version...')
        versionAction.triggered.connect(self.showVersion)
        
    def setupMainWidget(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout()

        # Create splitter - starts horizontal for tree view
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        # Allow children to be collapsed to very small sizes (user can drag splitter far in either direction)
        self.splitter.setChildrenCollapsible(True)

        # Create terminal first
        self.terminal = TerminalWidget()

        # Use the new unified AgentDisplayWidget (includes tree, table, and graph views)
        self.agent_display = AgentDisplayWidget(self.terminal)
        # Set very small minimum size to allow flexible splitter positioning
        self.agent_display.setMinimumWidth(50)
        self.terminal.setMinimumWidth(50)
        self.splitter.addWidget(self.agent_display)

        # Keep agent_tree reference for backward compatibility (points to tree_widget inside agent_display)
        self.agent_tree = self.agent_display.tree_widget

        # Add this line to set the agent_tree reference in the terminal
        self.terminal.agent_tree = self.agent_tree

        # Add terminal and logs in tabs
        self.splitter.addWidget(self.terminal)

        # Set initial sizes for the splitter (more space for terminal on the right)
        # First value is agent panel, second is terminal
        self.splitter.setSizes([560, 1040])

        # Connect view change signal to adjust layout
        self.agent_display.view_changed.connect(self.on_agent_view_changed)

        layout.addWidget(self.splitter)
        main_widget.setLayout(layout)

        # ADD FLOATING STATUS INDICATOR
        self.status_indicator = FloatingStatusIndicator(self)
        self.status_indicator.show()
        self.status_indicator.raise_()  # Keep on top

    def on_agent_view_changed(self, view_id):
        """Adjust splitter orientation based on the active view.

        Tree view (0): Horizontal split (agents left, terminal right)
        Table view (1): Vertical split (agents top, terminal bottom) - like Cobalt Strike
        Graph view (2): Horizontal split (graph left, terminal right)

        Remembers splitter sizes per view so user adjustments persist.
        """
        # Save current view's splitter sizes before switching
        if hasattr(self, '_current_view_id'):
            self._save_view_splitter_sizes(self._current_view_id)

        # Update current view tracker
        self._current_view_id = view_id

        if view_id == 1:  # Table view
            # Switch to vertical layout (table on top, terminal below)
            if self.splitter.orientation() != Qt.Orientation.Vertical:
                self.splitter.setOrientation(Qt.Orientation.Vertical)

            # Restore saved sizes for table view, or use defaults (more terminal space)
            saved_sizes = self._get_view_splitter_sizes(view_id)
            if saved_sizes:
                self.splitter.setSizes(saved_sizes)
            else:
                # Default: 20% table (top), 80% terminal (bottom) - more terminal space
                new_total = self.splitter.height()
                self.splitter.setSizes([int(new_total * 0.20), int(new_total * 0.80)])
        else:  # Tree or Graph view
            # Switch to horizontal layout (agents left, terminal right)
            if self.splitter.orientation() != Qt.Orientation.Horizontal:
                self.splitter.setOrientation(Qt.Orientation.Horizontal)

            # Restore saved sizes for this view, or use defaults
            saved_sizes = self._get_view_splitter_sizes(view_id)
            if saved_sizes:
                self.splitter.setSizes(saved_sizes)
            else:
                # Default: 35% agents (left), 65% terminal (right)
                new_total = self.splitter.width()
                self.splitter.setSizes([int(new_total * 0.35), int(new_total * 0.65)])

    def _save_view_splitter_sizes(self, view_id):
        """Save the current splitter sizes for a specific view."""
        if not hasattr(self, '_view_splitter_sizes'):
            self._view_splitter_sizes = {}
        self._view_splitter_sizes[view_id] = self.splitter.sizes()

    def _get_view_splitter_sizes(self, view_id):
        """Get saved splitter sizes for a specific view, or None if not saved."""
        if not hasattr(self, '_view_splitter_sizes'):
            self._view_splitter_sizes = {}
        return self._view_splitter_sizes.get(view_id)

    def showCNADebugConsole(self):
        """Show the CNA debug console"""
        from .widgets.cna_debug_console import CNADebugConsole
        
        # Get current terminal and interpreter
        current_widget = self.terminal.tabs.currentWidget()
        cna_interpreter = None
        
        if hasattr(current_widget, 'command_handler') and hasattr(current_widget.command_handler, 'cna_interpreter'):
            cna_interpreter = current_widget.command_handler.cna_interpreter
        
        # Create debug console if it doesn't exist or was closed
        if not hasattr(self, 'cna_debug_console') or not self.cna_debug_console.isVisible():
            self.cna_debug_console = CNADebugConsole(self, cna_interpreter)
            
            # Link the debug console to the interpreter
            if cna_interpreter:
                cna_interpreter.set_debug_console(self.cna_debug_console)
                self.cna_debug_console.log("INFO", "CONSOLE", "Debug console connected to CNA interpreter")
            else:
                self.cna_debug_console.log("WARNING", "CONSOLE", "No CNA interpreter found - select an agent terminal first")
        
        # Show as non-modal window
        self.cna_debug_console.show()
        self.cna_debug_console.raise_()
        self.cna_debug_console.activateWindow()
    
    def loadCNAScript(self):
        """Load a CNA script file globally with persistence"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select CNA Script",
            "",
            "CNA Scripts (*.cna);;All Files (*)"
        )

        if file_path:
            # Use the shared CNA manager instance (initialized in __init__)
            if self.cna_manager.load_script(file_path, persist=True):
                # Apply to all existing terminals
                for agent_guid, terminal in self.terminal.agent_terminals.items():
                    self.cna_manager.apply_to_terminal(terminal)

                QMessageBox.information(self, "Success",
                    f"CNA script loaded and will be remembered for future sessions:\n{file_path}")
            else:
                # Get the last error for more helpful message
                errors = self.cna_manager.get_startup_errors()
                error_msg = errors[-1]['error'] if errors else "Unknown error"
                QMessageBox.warning(self, "Error",
                    f"Failed to load CNA script:\n{file_path}\n\nError: {error_msg}")
            
    def manageCNAScripts(self):
        """Manage loaded CNA scripts with persistence info"""

        dialog = QDialog(self)
        dialog.setWindowTitle("Manage CNA Scripts")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(450)
        
        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("CNA Scripts (persisted for auto-load on startup):")
        layout.addWidget(info_label)

        # List widget for scripts
        script_list = QListWidget()

        # Get persisted scripts from database (including failed ones)
        persisted_scripts = self.cna_manager.get_persisted_scripts(include_disabled=True)
        loaded_scripts = self.cna_manager.loaded_scripts

        # Also check current terminal interpreter
        current_widget = self.terminal.tabs.currentWidget()
        cmd_count = 0
        if hasattr(current_widget, 'command_handler') and hasattr(current_widget.command_handler, 'cna_interpreter'):
            cmd_count = len(current_widget.command_handler.cna_interpreter.commands)

        # Add scripts with status indicators
        for script_info in persisted_scripts:
            script_path = script_info['script_path']
            is_loaded = script_path in loaded_scripts
            has_error = script_info.get('last_error') is not None
            is_enabled = script_info.get('enabled', True)

            # Build display text with status
            basename = os.path.basename(script_path)
            if not is_enabled:
                display_text = f"[DISABLED] {script_path}"
            elif has_error:
                display_text = f"[FAILED] {script_path}"
            elif is_loaded:
                display_text = f"[LOADED] {script_path}"
            else:
                display_text = script_path

            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, script_path)  # Store actual path

            # Color code based on status
            if not is_enabled:
                item.setForeground(QColor(128, 128, 128))  # Gray
            elif has_error:
                item.setForeground(QColor(255, 100, 100))  # Red
                item.setToolTip(f"Error: {script_info['last_error']}")
            elif is_loaded:
                item.setForeground(QColor(100, 255, 100))  # Green

            script_list.addItem(item)

        # Also add any loaded scripts not in persistence (edge case)
        for script_path in loaded_scripts:
            if not any(s['script_path'] == script_path for s in persisted_scripts):
                item = QListWidgetItem(f"[LOADED-TEMP] {script_path}")
                item.setData(Qt.ItemDataRole.UserRole, script_path)
                item.setForeground(QColor(255, 200, 100))  # Orange
                item.setToolTip("Loaded but not persisted - will not auto-load on restart")
                script_list.addItem(item)

        info_label.setText(f"CNA Scripts ({cmd_count} commands registered, {len(loaded_scripts)} loaded):")
        
        layout.addWidget(script_list)
        
        # Registration mode selector
        mode_layout = QHBoxLayout()
        mode_label = QLabel("Registration Mode:")
        mode_combo = QComboBox()
        mode_combo.addItems(["both", "direct", "bof"])
        
        if hasattr(current_widget, 'command_handler') and hasattr(current_widget.command_handler, 'cna_interpreter'):
            mode_combo.setCurrentText(interpreter.registration_mode)
            mode_combo.currentTextChanged.connect(
                lambda mode: self._set_cna_registration_mode(mode)
            )
        
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(mode_combo)
        mode_layout.addWidget(QLabel("(both=direct+bof, direct=as-is, bof=via 'bof' command)"))
        mode_layout.addStretch()
        layout.addLayout(mode_layout)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Add script button
        add_button = QPushButton("Add Script...")
        add_button.clicked.connect(lambda: self._add_cna_script(script_list))
        button_layout.addWidget(add_button)
        
        # Remove script button
        remove_button = QPushButton("Remove Selected")
        remove_button.clicked.connect(lambda: self._remove_cna_script(script_list))
        button_layout.addWidget(remove_button)
        
        # Reload all button
        reload_button = QPushButton("Reload All")
        reload_button.clicked.connect(lambda: self._reload_cna_scripts(script_list))
        button_layout.addWidget(reload_button)

        # View Log button
        log_button = QPushButton("View Log")
        log_button.clicked.connect(self._view_cna_log)
        log_button.setToolTip(f"View startup error log:\n{self.cna_manager.get_log_path()}")
        button_layout.addWidget(log_button)

        # Close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)

        # Add log path info at bottom
        log_info = QLabel(f"Startup log: {self.cna_manager.get_log_path()}")
        log_info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(log_info)

        dialog.setLayout(layout)
        dialog.exec()
    
    def _set_cna_registration_mode(self, mode: str):
        """Set the CNA command registration mode"""
        current_widget = self.terminal.tabs.currentWidget()
        if hasattr(current_widget, 'command_handler') and hasattr(current_widget.command_handler, 'cna_interpreter'):
            interpreter = current_widget.command_handler.cna_interpreter
            interpreter.set_registration_mode(mode)
            
            # Log to debug console if open
            if hasattr(self, 'cna_debug_console') and self.cna_debug_console.isVisible():
                self.cna_debug_console.log("INFO", "CONFIG", f"Registration mode changed to: {mode}")
            
            QMessageBox.information(self, "Mode Changed", 
                f"Registration mode set to: {mode}\n\n"
                f"• both: Commands available directly AND via 'bof <cmd>'\n"
                f"• direct: Commands available directly (e.g., 'dir')\n"
                f"• bof: Commands only via 'bof <cmd>' (e.g., 'bof dir')\n\n"
                f"Reload scripts for changes to take effect.")
    
    def _add_cna_script(self, script_list):
        """Add a new CNA script with persistence"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select CNA Script to Add",
            "",
            "CNA Scripts (*.cna);;All Files (*)"
        )

        if file_path:
            # Use the shared CNA manager for persistence
            if self.cna_manager.load_script(file_path, persist=True):
                # Also load into the current terminal's interpreter
                current_widget = self.terminal.tabs.currentWidget()
                if hasattr(current_widget, 'command_handler'):
                    current_widget.command_handler.load_cna_script(file_path)

                # Apply to all terminals
                for agent_guid, terminal in self.terminal.agent_terminals.items():
                    self.cna_manager.apply_to_terminal(terminal)

                script_list.addItem(file_path)
                QMessageBox.information(self, "Success",
                    "Script added and will load automatically on startup")
            else:
                errors = self.cna_manager.get_startup_errors()
                error_msg = errors[-1]['error'] if errors else "Unknown error"
                QMessageBox.warning(self, "Error",
                    f"Failed to add script:\n{error_msg}")
    
    def _remove_cna_script(self, script_list):
        """Remove selected CNA script and clean up its registrations"""
        current_item = script_list.currentItem()
        if current_item:
            # Get actual path from UserRole data (display text has status prefix)
            script_path = current_item.data(Qt.ItemDataRole.UserRole)
            if not script_path:
                script_path = current_item.text()  # Fallback for old items

            reply = QMessageBox.question(self, 'Remove Script',
                f'Remove CNA script and unregister its commands?\n\n'
                f'{script_path}\n\n'
                f'This will also remove it from auto-load on startup.',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

            if reply == QMessageBox.StandardButton.Yes:
                # Get current terminal and interpreter
                current_widget = self.terminal.tabs.currentWidget()
                if hasattr(current_widget, 'command_handler') and \
                hasattr(current_widget.command_handler, 'cna_interpreter'):
                    interpreter = current_widget.command_handler.cna_interpreter

                    # Unload the script from interpreter
                    interpreter.unload_script(script_path)

                    # Also unload from global CNA manager and database
                    self.cna_manager.unload_script(script_path, remove_from_db=True)

                    # Update UI
                    script_list.takeItem(script_list.row(current_item))

                    # Update debug console if open
                    if hasattr(self, 'cna_debug_console') and self.cna_debug_console.isVisible():
                        self.cna_debug_console.refresh_status()

                    QMessageBox.information(self, "Removed",
                        f"Script removed and will not load on future startups:\n{os.path.basename(script_path)}")

    def _reload_cna_scripts(self, script_list):
        """Reload all CNA scripts"""
        current_widget = self.terminal.tabs.currentWidget()
        if hasattr(current_widget, 'command_handler') and hasattr(current_widget.command_handler, 'cna_interpreter'):
            interpreter = current_widget.command_handler.cna_interpreter
            
            # Save script paths
            script_paths = list(interpreter.loaded_scripts)
            
            # Clear interpreter
            interpreter.commands.clear()
            interpreter.aliases.clear()
            interpreter.loaded_scripts.clear()
            
            # Clear command validator's CNA commands
            if hasattr(current_widget.command_validator, 'cna_commands'):
                current_widget.command_validator.cna_commands.clear()
            
            # Reload all scripts
            failed_scripts = []
            for script_path in script_paths:
                if not current_widget.command_handler.load_cna_script(script_path):
                    failed_scripts.append(script_path)
            
            if failed_scripts:
                QMessageBox.warning(self, "Reload Issues",
                    f"Failed to reload {len(failed_scripts)} script(s):\n" +
                    "\n".join(failed_scripts))
            else:
                QMessageBox.information(self, "Success",
                    f"Successfully reloaded {len(script_paths)} script(s)")

    def _view_cna_log(self):
        """Open the CNA startup log file"""
        import subprocess
        import sys

        log_path = self.cna_manager.get_log_path()

        if not log_path.exists():
            QMessageBox.information(self, "No Log File",
                f"No CNA startup log exists yet.\n\n"
                f"Log will be created at:\n{log_path}\n\n"
                f"Errors during startup script loading will be logged here.")
            return

        try:
            # Open with system default text editor
            if sys.platform == 'win32':
                os.startfile(str(log_path))
            elif sys.platform == 'darwin':
                subprocess.run(['open', str(log_path)])
            else:
                # Linux - try common editors
                for editor in ['xdg-open', 'gedit', 'kate', 'nano', 'vim']:
                    try:
                        subprocess.Popen([editor, str(log_path)])
                        break
                    except FileNotFoundError:
                        continue
        except Exception as e:
            QMessageBox.warning(self, "Error",
                f"Could not open log file:\n{e}\n\nLog path:\n{log_path}")

    def showDownloads(self):
        """Show the downloads tab and request latest manifest"""
        # Create and add downloads tab if it doesn't exist
        downloads_found = False
        for i in range(self.terminal.tabs.count()):
            if self.terminal.tabs.tabText(i) == "Downloads":
                self.terminal.tabs.setCurrentIndex(i)
                downloads_found = True
                break
                
        if not downloads_found:
            # Create new downloads widget
            self.downloads_widget = DownloadsWidget()
            if self.ws_thread:
                self.downloads_widget.set_ws_thread(self.ws_thread)
            tab_index = self.terminal.tabs.addTab(self.downloads_widget, "Downloads")
            self.terminal.tabs.setCurrentIndex(tab_index)

        # Request latest manifest if connected
        if self.ws_thread and self.ws_thread.is_connected():
            self.ws_thread.request_downloads_manifest_sync()
            self.terminal.log_message("Requested downloads manifest from server")
        else:
            self.terminal.log_message("Not connected to server")

    def showConnectDialog(self):
        # Show connecting status before dialog opens
        self.status_indicator.set_connecting()
        
        dialog = ServerConnectDialog(self, terminal_widget=self.terminal)
        result = dialog.exec()
        
        if result and dialog.ws_thread:
            print("MainWindow: Dialog accepted, setting up WebSocket thread")
            self.ws_thread = dialog.ws_thread
            
            # Set up connections
            self.agent_tree.ws_thread = self.ws_thread
            self.terminal.set_ws_thread(self.ws_thread)
            
            # IMPORTANT: Connect to thread-safe handler for status updates
            self.ws_thread.connected.connect(self.handle_connection_status)
            
            self.ws_thread.disconnected.connect(self.onDisconnected)
            self.ws_thread.message_received.connect(self.onMessageReceived)
            self.ws_thread.log_message.connect(self.onLogMessage)
            self.ws_thread.listener_update.connect(self.onListenerUpdate)
            self.ws_thread.state_received.connect(self.loadInitialState)
            
            # Connect signals - use agent_display for proper delegation to all views
            self.ws_thread.connection_update.connect(self.agent_display.handle_new_connection)
            self.ws_thread.connection_update.connect(self.onConnectionUpdate)
            self.ws_thread.link_update.connect(self.agent_display.handle_link_update)
            
            # The connection is already established at this point, so directly set status to connected
            self.status_indicator.set_connected()
            self.is_connected = True
            self.updateMenuState()
            
            # Add this: Connect downloads widget if it exists
            if hasattr(self, 'downloads_widget'):
                self.downloads_widget.set_ws_thread(self.ws_thread)

            # Connect listeners widget if it exists
            if hasattr(self, 'listeners_widget'):
                self.listeners_widget.set_ws_thread(self.ws_thread)

            print("MainWindow: WebSocket thread setup complete")
        else:
            # Dialog was cancelled or connection failed
            self.status_indicator.set_disconnected()
            print("MainWindow: Connection dialog cancelled or failed")

    def handle_connection_status(self, connected, message):
        """Thread-safe handler for connection status updates"""
        # Use QMetaObject.invokeMethod to ensure this runs in the main thread
        QMetaObject.invokeMethod(
            self,
            "_update_connection_status",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(bool, connected),
            Q_ARG(str, message)
        )
    
    @pyqtSlot(bool, str)
    def _update_connection_status(self, connected, message):
        """Update connection status in the main thread"""
        print(f"MainWindow: Updating connection status - connected: {connected}, message: {message}")
        
        if connected:
            self.status_indicator.set_connected()
            self.is_connected = True
        else:
            # Check message to determine the status
            message_lower = message.lower()
            
            # Check for max reconnection attempts reached
            if "failed to reconnect" in message_lower and "attempts" in message_lower:
                # This is the final failure message after max attempts
                self.status_indicator.set_disconnected()
                self.is_connected = False
            # Check for initial connection failure
            elif "failed to connect" in message_lower and "ensure the server is running" in message_lower:
                self.status_indicator.set_disconnected()
                self.is_connected = False
            # Check for active reconnection attempts
            elif any(word in message_lower for word in ["retry", "retrying", "attempting", "reconnect"]):
                self.status_indicator.set_connecting()
            # Any other disconnection messages
            else:
                self.status_indicator.set_disconnected()
                self.is_connected = False
        
        self.updateMenuState()
        self.terminal.log_message(message)

    def onListenerUpdate(self, event, listener_data):
        """Handle listener updates from the server"""
        print(f"MainWindow: Received listener update - Event: {event}, Data: {listener_data}")

        # Check if 'listener' key exists in listener_data or if the data is already flattened
        if 'listener' in listener_data:
            listener_details = listener_data['listener']
        else:
            listener_details = listener_data

        if event == "created":
            listener_id = listener_details['id']

            # Add listener to the tree if it hasn't been processed yet
            if listener_id not in self.processed_listener_ids:
                print("MainWindow: Adding new listener to tree after broadcast update")
                self.agent_display.add_listener(
                    name=listener_details['name'],
                    protocol=listener_details['protocol'],
                    host=listener_details.get('ip', ''),
                    port=str(listener_details.get('port', '')),
                    pipe_name=listener_details.get('pipe_name', ''),
                    get_profile=listener_details.get('get_profile', ''),
                    post_profile=listener_details.get('post_profile', ''),
                    server_response_profile=listener_details.get('server_response_profile', '')
                )
                self.terminal.log_message(f"New listener added: {listener_details['name']}")
                # Mark this listener as processed
                self.processed_listener_ids.add(listener_id)

                # Also update ListenersWidget if it exists and is visible
                if hasattr(self, 'listeners_widget'):
                    print("MainWindow: Updating ListenersWidget with new listener")
                    self.listeners_widget.add_listener(listener_details)
            else:
                print(f"MainWindow: Listener '{listener_details['name']}' already exists. Skipping addition.")

        elif event == "deleted":
            listener_name = listener_details.get('name', listener_details.get('name', ''))
            print(f"MainWindow: Removing listener: {listener_name}")
            self.agent_display.remove_listener(listener_name)
            self.terminal.log_message(f"Listener {listener_name} has been deleted")
            # Remove the listener ID from the processed set if it was stored
            self.processed_listener_ids.discard(listener_name)

            # Also update ListenersWidget if it exists
            if hasattr(self, 'listeners_widget'):
                print("MainWindow: Removing listener from ListenersWidget")
                self.listeners_widget.remove_listener_row(listener_name)

    def onLogMessage(self, message):
        """Handle log messages emitted from the WebSocketThread."""
        self.terminal.log_message(message)

    def onMessageReceived(self, message):
        """Log messages received from the WebSocket thread."""
        try:
            msg_data = json.loads(message)
            if msg_data.get('type') != 'binary_chunk':
                self.terminal.log_message(message)
        except json.JSONDecodeError:
            pass
    
    def showListeners(self):
        """Show the listeners tab and refresh the data."""
        # Check if listeners tab already exists
        listeners_found = False
        for i in range(self.terminal.tabs.count()):
            if self.terminal.tabs.tabText(i) == "Listeners":
                self.terminal.tabs.setCurrentIndex(i)
                listeners_found = True
                # Refresh the data
                widget = self.terminal.tabs.widget(i)
                if hasattr(widget, 'refresh_listeners'):
                    widget.refresh_listeners()
                break

        if not listeners_found:
            # Create new listeners widget
            self.listeners_widget = ListenersWidget(self.agent_tree, self.ws_thread)
            tab_index = self.terminal.tabs.addTab(self.listeners_widget, "Listeners")
            self.terminal.tabs.setCurrentIndex(tab_index)
            # Refresh to populate data
            self.listeners_widget.refresh_listeners()

        self.terminal.log_message("Opened Listeners view")

    def resizeEvent(self, event):
        """Handle window resize to reposition floating indicator"""
        super().resizeEvent(event)
        if hasattr(self, 'status_indicator'):
            self.status_indicator.reposition()

    def showEvent(self, event):
        """Handle window show event to apply initial view after layout is complete"""
        super().showEvent(event)
        if not self._initial_view_applied:
            self._initial_view_applied = True
            # Use a short delay to ensure layout is fully settled
            QTimer.singleShot(50, self._apply_default_view)

    def updateMenuState(self):
        serverMenu = self.menuBar().findChild(QMenu, "Server")
        if serverMenu:
            actions = serverMenu.actions()
            if actions:
                connectAction = actions[0]
                disconnectAction = actions[1]
                connectAction.setEnabled(not self.is_connected)
                disconnectAction.setEnabled(self.is_connected)

    def changeEvent(self, event):
        """Handle window state changes - auto-dismiss notifications when window is activated."""
        from PyQt6.QtCore import QEvent
        if event.type() == QEvent.Type.ActivationChange:
            if self.isActiveWindow():
                # Window just became active - dismiss any pending notifications
                if hasattr(self, 'notification_manager'):
                    self.notification_manager.on_main_window_focused()
        super().changeEvent(event)

    def save_window_state(self):
        """Save window geometry, splitter state, and view-specific layouts"""
        try:
            # Save current view's splitter sizes before saving
            if hasattr(self, '_current_view_id'):
                self._save_view_splitter_sizes(self._current_view_id)

            state = {
                'geometry': {
                    'x': self.x(),
                    'y': self.y(),
                    'width': self.width(),
                    'height': self.height()
                },
                'splitter_sizes': self.splitter.sizes() if hasattr(self, 'splitter') else [300, 900],
                'current_view_id': getattr(self, '_current_view_id', 0),
                'view_splitter_sizes': getattr(self, '_view_splitter_sizes', {})
            }

            with open(self.window_state_file, 'w') as f:
                json.dump(state, f, indent=2)

            print(f"Window state saved: {state}")
        except Exception as e:
            print(f"Failed to save window state: {e}")

    def restore_window_state(self):
        """Restore window geometry, splitter state, and view-specific layouts"""
        try:
            if self.window_state_file.exists():
                with open(self.window_state_file, 'r') as f:
                    state = json.load(f)

                # Restore window geometry
                geom = state.get('geometry', {})
                if geom:
                    self.setGeometry(
                        geom.get('x', 100),
                        geom.get('y', 100),
                        geom.get('width', 1200),
                        geom.get('height', 800)
                    )

                # Restore splitter sizes
                if hasattr(self, 'splitter'):
                    sizes = state.get('splitter_sizes', [300, 900])
                    self.splitter.setSizes(sizes)

                # Restore view-specific splitter sizes (convert string keys back to int)
                saved_view_sizes = state.get('view_splitter_sizes', {})
                self._view_splitter_sizes = {int(k): v for k, v in saved_view_sizes.items()}

                # Restore current view ID tracker
                self._current_view_id = state.get('current_view_id', 0)

                print(f"Window state restored: {state}")
        except Exception as e:
            print(f"Failed to restore window state: {e}")

    def closeEvent(self, event):
        """Handle application close event with proper cleanup"""
        print("MainWindow: Close event triggered")

        # Save window state before closing
        self.save_window_state()

        # Stop any timers in the agent tree widget
        if hasattr(self, 'agent_tree') and hasattr(self.agent_tree, 'last_seen_timer'):
            print("MainWindow: Stopping agent tree timer...")
            self.agent_tree.last_seen_timer.stop()

        # Stop the WebSocket thread if it exists
        if hasattr(self, 'ws_thread') and self.ws_thread:
            print("MainWindow: Stopping WebSocket thread...")
            self.ws_thread.stop()

            # Wait for the thread to finish with a timeout
            if self.ws_thread.isRunning():
                print("MainWindow: Waiting for WebSocket thread to finish...")
                if not self.ws_thread.wait(5000):  # 5 second timeout
                    print("MainWindow: WebSocket thread didn't stop cleanly, terminating...")
                    self.ws_thread.terminate()
                    self.ws_thread.wait(1000)  # Give it 1 more second

            self.ws_thread = None
            print("MainWindow: WebSocket thread cleanup complete")

        # Close any open dialogs
        for widget in self.findChildren(QDialog):
            widget.close()

        # Cleanup notification manager
        if hasattr(self, 'notification_manager'):
            print("MainWindow: Cleaning up notification manager...")
            self.notification_manager.cleanup()

        # Accept the close event
        event.accept()

        # Call parent class closeEvent
        super().closeEvent(event)

        print("MainWindow: Close event complete")

        # Force quit the application
        QApplication.instance().quit()

    def disconnectFromServer(self):
        """Disconnect from server cleanly"""
        if not self.ws_thread or not self.ws_thread.isRunning():
            QMessageBox.information(self, "Disconnect", "No active connection to disconnect.")
            return
        
        print("MainWindow: Disconnecting from server...")
        
        # Stop the WebSocket thread
        self.ws_thread.stop()
        
        # Wait for it to finish with timeout
        if not self.ws_thread.wait(3000):  # 3 second timeout
            print("MainWindow: WebSocket thread didn't stop cleanly during disconnect")
            self.ws_thread.terminate()
            self.ws_thread.wait(1000)
        
        self.ws_thread = None
        self.is_connected = False
        self.status_indicator.set_disconnected()
        self.updateMenuState()
        self.terminal.log_message("Disconnected from server")
        
        print("MainWindow: Disconnection complete")

    def setupConnections(self):
        # Ensure ws_thread signals are connected
        if self.ws_thread:
            self.ws_thread.connected.connect(self.onConnected)
            self.ws_thread.disconnected.connect(self.onDisconnected)

    def onDisconnected(self):
        print("MainWindow: Connection disconnected")
        
        # Update floating status indicator
        self.status_indicator.set_disconnected()
        
        if self.ws_thread:
            self.ws_thread.wait()
            self.ws_thread = None
            # Clear AgentDisplayWidget's ws_thread reference (propagates to tree)
            self.agent_display.ws_thread = None
            # Add this: Clear downloads widget's ws_thread reference if it exists
            if hasattr(self, 'downloads_widget'):
                self.downloads_widget.ws_thread = None
            # Clear listeners widget's ws_thread reference if it exists
            if hasattr(self, 'listeners_widget'):
                self.listeners_widget.ws_thread = None
            print("MainWindow: Cleared AgentDisplayWidget ws_thread reference")

        self.is_connected = False
        self.updateMenuState()

    def showCreateListener(self):
        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Warning", "Please connect to server first")
            return

        # Pass database reference for profile dropdown population
        db = self.ws_thread.db if self.ws_thread else None
        dialog = CreateListenerDialog(self, self.ws_thread, db)
        dialog.exec()

    def showCreatePayload(self):
        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Warning", "Please connect to server first")
            return
        
        dialog = CreatePayloadDialog(self, self.ws_thread, self.agent_tree)
        if dialog.exec():
            # Dialog closes immediately after sending request
            # Store the output path for background chunk handling
            self.pending_payload = {
                'output_path': dialog.output_path.text(),
                'chunks': set(),
                'expected_chunks': 0,
                'file_name': None,
                'temp_file': None
            }
            
            # Connect handler if not already connected
            if not hasattr(self, '_payload_handler_connected'):
                self.ws_thread.message_received.connect(self.handle_payload_message)
                self._payload_handler_connected = True

    def loadInitialState(self):
        print("\nMainWindow: Loading initial state")
        self.agent_display.ws_thread = self.ws_thread

        # Set view to agents by default
        self.agent_tree.current_view = 'agents'

        # Load the state via agent_display (delegates to tree and refreshes other views)
        self.agent_display.loadStateFromDatabase()
        self.sync_with_database()

        # Sync agent aliases from agent_tree to terminal widget
        if hasattr(self.agent_tree, 'agent_aliases'):
            self.terminal.agent_aliases = self.agent_tree.agent_aliases.copy()
            print(f"MainWindow: Synced {len(self.terminal.agent_aliases)} agent aliases to terminal widget")

        # Emit the state loaded signal
        self.state_loaded.emit()

    def onConnectionUpdate(self, conn_data):
        """Handle new connection updates from the server"""
        print(f"MainWindow: Received connection update: {conn_data}")
        try:
            print("MainWindow: Passing connection data to AgentDisplayWidget")
            self.agent_display.handle_new_connection(conn_data)
            print("MainWindow: Successfully handled new connection")

            # Send notification for new agent
            if hasattr(self, 'notification_manager'):
                self.notification_manager.notify_new_agent(conn_data)

        except Exception as e:
            print(f"ERROR in onConnectionUpdate: {e}")
            import traceback
            traceback.print_exc()

    def sync_with_database(self):
        """Synchronize state with local database without creating terminal tabs"""
        print("MainWindow: Synchronizing state with local database...")

        # Load state from database
        state = self.state_db.fetch_commands_and_outputs()
        commands = state.get("commands", [])
        outputs = state.get("outputs", [])

        print(f"MainWindow: Retrieved {len(commands)} commands and {len(outputs)} outputs from database.")

        # Create a dictionary to group outputs by command_id for faster lookup
        outputs_by_command = {}
        for output in outputs:
            command_id = output[1]  # Index 1 contains command_id
            if command_id not in outputs_by_command:
                outputs_by_command[command_id] = []
            outputs_by_command[command_id].append(output)

        # Store the command history in the terminal widget
        self.terminal.store_command_history(
            sorted(commands, key=lambda x: x[4]),  # Sort commands by timestamp
            outputs_by_command
        )

        print("MainWindow: State synchronization complete.")

    def handle_payload_message(self, message_json):
        """Handle binary chunks in the background after dialog closes"""
        if not hasattr(self, 'pending_payload'):
            return
        
        try:
            message = json.loads(message_json)
            message_type = message.get("type")
            
            if message_type == "binary_chunk":
                chunk_num = message.get('chunk_num')
                total_chunks = message.get('total_chunks')
                file_name = message.get('file_name')
                chunk_data = message.get('data')
                
                # Initialize on first chunk
                if not self.pending_payload['file_name']:
                    self.pending_payload['file_name'] = file_name
                    self.pending_payload['expected_chunks'] = total_chunks
                    temp_path = os.path.join(self.pending_payload['output_path'], f"{file_name}.temp")
                    self.pending_payload['temp_file'] = temp_path
                    open(temp_path, 'wb').close()  # Create empty file
                
                # Write chunk to temp file
                with open(self.pending_payload['temp_file'], 'ab') as f:
                    f.write(base64.b64decode(chunk_data))
                
                self.pending_payload['chunks'].add(chunk_num)
                
            elif message_type == "binary_transfer_complete":
                data = message.get('data', {})
                status = data.get('status')
                
                if status == "success":
                    # Rename temp to final
                    final_path = os.path.join(
                        self.pending_payload['output_path'],
                        self.pending_payload['file_name']
                    )
                    if os.path.exists(self.pending_payload['temp_file']):
                        os.rename(self.pending_payload['temp_file'], final_path)
                        QMessageBox.information(self, "Success", "Payload generated successfully!")
                    else:
                        QMessageBox.warning(self, "Error", "Payload file not found")
                else:
                    QMessageBox.warning(self, "Error", f"Payload generation failed: {status}")
                    # Clean up temp file if it exists
                    if self.pending_payload.get('temp_file') and os.path.exists(self.pending_payload['temp_file']):
                        os.remove(self.pending_payload['temp_file'])
                
                # Clean up
                del self.pending_payload
                
        except Exception as e:
            print(f"MainWindow: Error handling payload message: {e}")

    def showSettings(self):
        """Show settings dialog"""
        dialog = SettingsDialog(self)
        dialog.theme_changed.connect(self.apply_theme)
        dialog.settings_changed.connect(self.on_settings_changed)
        if dialog.exec():
            print("Settings saved")

    def on_settings_changed(self, settings):
        """Handle settings changes - apply them to relevant components."""
        self.app_settings = settings

        # Reload notification manager settings
        if hasattr(self, 'notification_manager'):
            self.notification_manager.reload_settings()

        # Update GUID display length in agent tree and refresh views
        guid_length = settings.get('guid_display_length', 16)
        if hasattr(self, 'agent_tree'):
            self.agent_tree.guid_display_length = guid_length
            # Refresh the tree to apply new GUID length
            if self.agent_tree.current_view == 'agents':
                self.agent_tree.show_agents()
            # Refresh table view
            if hasattr(self, 'agent_display'):
                self.agent_display.table_widget.refresh_from_tree()
                self.agent_display.graph_widget.refresh_graph()

        print(f"Settings applied: {settings}")
    
    def showVersion(self):
        """Show version dialog"""
        dialog = VersionDialog(self)
        dialog.exec()
    
    def apply_theme(self, theme_name):
        """Apply the selected theme to the application"""
        print(f"==> apply_theme() called with: '{theme_name}'")
        
        # Map themes to their methods and terminal theme names
        theme_map = {
            "Dark": (self.set_dark_theme, "dark", True),
            "Light": (self.set_light_theme, "light", False),
            "Dracula": (self.set_dracula_theme, "dracula", True),
            "Monokai": (self.set_monokai_theme, "monokai", True),
            "Nord": (self.set_nord_theme, "nord", True),
            "Solarized Dark": (self.set_solarized_dark_theme, "solarized_dark", True),
            "Gruvbox": (self.set_gruvbox_theme, "gruvbox", True),
            "One Dark": (self.set_one_dark_theme, "one_dark", True),
            "Brandon's Hotdog Stand": (self.set_hotdog_stand_theme, "hotdog_stand", False)
        }
        
        if theme_name in theme_map:
            theme_method, terminal_theme, is_dark = theme_map[theme_name]
            theme_method()
            self.update_terminal_themes(terminal_theme)
            self.update_window_decorations(is_dark)  # ADD THIS LINE
        else:
            # Default to dark theme if unknown
            self.set_dark_theme()
            self.update_terminal_themes("dark")
            self.update_window_decorations(True) 

    def set_dark_theme_with_window_style(self):
        """Apply dark theme with window styling"""
        dark_stylesheet = """
            /* Your existing QMainWindow, QDialog, QWidget styles... */
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #1e1e1e;  /* This styles the window border */
            }
            /* ... rest of your stylesheet ... */
        """
        self.setStyleSheet(dark_stylesheet)
        
        # Also set window palette for title bar
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
        self.setPalette(palette)

    def apply_platform_specific_dark_mode(self):
        """
        Apply platform-specific dark mode settings.
        Call this in __init__ or initUI for best results.
        """
        import platform
        import sys
        
        system = platform.system()
        
        if system == "Windows":
            # Windows-specific dark title bar (Windows 10 1809+)
            try:
                import ctypes
                hwnd = int(self.winId())
                # DWMWA_USE_IMMERSIVE_DARK_MODE
                DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                value = ctypes.c_int(1)  # 1 for dark mode, 0 for light
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_USE_IMMERSIVE_DARK_MODE,
                    ctypes.byref(value),
                    ctypes.sizeof(value)
                )
            except Exception as e:
                print(f"Could not set Windows dark title bar: {e}")
        
        elif system == "Darwin":  # macOS
            # macOS doesn't need special handling - Qt respects system theme
            # But you can force it:
            try:
                from PyQt6.QtCore import Qt
                self.setAttribute(Qt.WidgetAttribute.WA_MacNormalSize)
            except:
                pass
        
        elif system == "Linux":
            # Linux/X11 - depends on window manager
            # Most modern window managers respect the application palette
            pass

    # ORIGINAL DARK THEME - KEEP THIS!
    def set_dark_theme(self):
        """Apply dark theme stylesheet"""
        dark_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #2b2b2b;
                color: #d4d4d4;
            }
            QMenuBar {
                background-color: #3c3c3c;
                color: #d4d4d4;
            }
            QMenuBar::item:selected {
                background-color: #4c4c4c;
            }
            QMenu {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555555;
            }
            QMenu::item:selected {
                background-color: #4c4c4c;
            }
            QPushButton {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #4c4c4c;
            }
            QPushButton:pressed {
                background-color: #2c2c2c;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555555;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #2b2b2b;
                color: #d4d4d4;
                border: 1px solid #555555;
                alternate-background-color: #323232;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #0d5aa7;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555555;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555555;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #4c4c4c;
            }
            QGroupBox {
                border: 1px solid #555555;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #d4d4d4;
            }
        """
        self.setStyleSheet(dark_stylesheet)
        print("Dark theme applied")

    # ORIGINAL LIGHT THEME - KEEP THIS!
    def set_light_theme(self):
        """Apply light theme (explicit light stylesheet)"""
        light_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #f5f5f5;
                color: #000000;
            }
            QMenuBar {
                background-color: #e0e0e0;
                color: #000000;
            }
            QMenuBar::item:selected {
                background-color: #d0d0d0;
            }
            QMenu {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
            }
            QMenu::item:selected {
                background-color: #0078d4;
                color: #ffffff;
            }
            QPushButton {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #e8e8e8;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #ffffff;
                color: #000000;
                border: 1px solid #cccccc;
                alternate-background-color: #f8f8f8;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #0078d4;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: #000000;
                border: 1px solid #cccccc;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
            }
            QGroupBox {
                border: 1px solid #cccccc;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #000000;
            }
        """
        self.setStyleSheet(light_stylesheet)
        print("Light theme applied")

    # NEW THEME 1: DRACULA
    def set_dracula_theme(self):
        """Apply Dracula theme - popular purple-tinted dark theme"""
        dracula_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #282a36;
                color: #f8f8f2;
            }
            QMenuBar {
                background-color: #44475a;
                color: #f8f8f2;
            }
            QMenuBar::item:selected {
                background-color: #6272a4;
            }
            QMenu {
                background-color: #44475a;
                color: #f8f8f2;
                border: 1px solid #6272a4;
            }
            QMenu::item:selected {
                background-color: #bd93f9;
                color: #282a36;
            }
            QPushButton {
                background-color: #44475a;
                color: #f8f8f2;
                border: 1px solid #6272a4;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #6272a4;
            }
            QPushButton:pressed {
                background-color: #bd93f9;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #44475a;
                color: #f8f8f2;
                border: 1px solid #6272a4;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #282a36;
                color: #f8f8f2;
                border: 1px solid #6272a4;
                alternate-background-color: #313442;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #bd93f9;
                color: #282a36;
            }
            QHeaderView::section {
                background-color: #44475a;
                color: #f8f8f2;
                border: 1px solid #6272a4;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #6272a4;
                background-color: #282a36;
            }
            QTabBar::tab {
                background-color: #44475a;
                color: #f8f8f2;
                border: 1px solid #6272a4;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #6272a4;
            }
            QGroupBox {
                border: 1px solid #6272a4;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #f8f8f2;
            }
        """
        self.setStyleSheet(dracula_stylesheet)
        print("Dracula theme applied")

    # NEW THEME 2: MONOKAI
    def set_monokai_theme(self):
        """Apply Monokai theme - warm, colorful dark theme"""
        monokai_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #272822;
                color: #f8f8f2;
            }
            QMenuBar {
                background-color: #3e3d32;
                color: #f8f8f2;
            }
            QMenuBar::item:selected {
                background-color: #49483e;
            }
            QMenu {
                background-color: #3e3d32;
                color: #f8f8f2;
                border: 1px solid #75715e;
            }
            QMenu::item:selected {
                background-color: #a6e22e;
                color: #272822;
            }
            QPushButton {
                background-color: #3e3d32;
                color: #f8f8f2;
                border: 1px solid #75715e;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #49483e;
            }
            QPushButton:pressed {
                background-color: #a6e22e;
                color: #272822;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #3e3d32;
                color: #f8f8f2;
                border: 1px solid #75715e;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #272822;
                color: #f8f8f2;
                border: 1px solid #75715e;
                alternate-background-color: #2d2e27;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #a6e22e;
                color: #272822;
            }
            QHeaderView::section {
                background-color: #3e3d32;
                color: #f8f8f2;
                border: 1px solid #75715e;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #75715e;
                background-color: #272822;
            }
            QTabBar::tab {
                background-color: #3e3d32;
                color: #f8f8f2;
                border: 1px solid #75715e;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #49483e;
            }
            QGroupBox {
                border: 1px solid #75715e;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #f8f8f2;
            }
        """
        self.setStyleSheet(monokai_stylesheet)
        print("Monokai theme applied")

    # NEW THEME 3: NORD
    def set_nord_theme(self):
        """Apply Nord theme - arctic, north-bluish color palette"""
        nord_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #2e3440;
                color: #eceff4;
            }
            QMenuBar {
                background-color: #3b4252;
                color: #eceff4;
            }
            QMenuBar::item:selected {
                background-color: #434c5e;
            }
            QMenu {
                background-color: #3b4252;
                color: #eceff4;
                border: 1px solid #4c566a;
            }
            QMenu::item:selected {
                background-color: #88c0d0;
                color: #2e3440;
            }
            QPushButton {
                background-color: #3b4252;
                color: #eceff4;
                border: 1px solid #4c566a;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #434c5e;
            }
            QPushButton:pressed {
                background-color: #88c0d0;
                color: #2e3440;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #3b4252;
                color: #eceff4;
                border: 1px solid #4c566a;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #2e3440;
                color: #eceff4;
                border: 1px solid #4c566a;
                alternate-background-color: #3b4252;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #88c0d0;
                color: #2e3440;
            }
            QHeaderView::section {
                background-color: #3b4252;
                color: #eceff4;
                border: 1px solid #4c566a;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #4c566a;
                background-color: #2e3440;
            }
            QTabBar::tab {
                background-color: #3b4252;
                color: #eceff4;
                border: 1px solid #4c566a;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #434c5e;
            }
            QGroupBox {
                border: 1px solid #4c566a;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #eceff4;
            }
        """
        self.setStyleSheet(nord_stylesheet)
        print("Nord theme applied")

    # NEW THEME 4: SOLARIZED DARK
    def set_solarized_dark_theme(self):
        """Apply Solarized Dark theme - precision colors for machines and people"""
        solarized_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #002b36;
                color: #839496;
            }
            QMenuBar {
                background-color: #073642;
                color: #839496;
            }
            QMenuBar::item:selected {
                background-color: #586e75;
            }
            QMenu {
                background-color: #073642;
                color: #839496;
                border: 1px solid #586e75;
            }
            QMenu::item:selected {
                background-color: #268bd2;
                color: #fdf6e3;
            }
            QPushButton {
                background-color: #073642;
                color: #839496;
                border: 1px solid #586e75;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #586e75;
            }
            QPushButton:pressed {
                background-color: #268bd2;
                color: #fdf6e3;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #073642;
                color: #839496;
                border: 1px solid #586e75;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #002b36;
                color: #839496;
                border: 1px solid #586e75;
                alternate-background-color: #073642;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #268bd2;
                color: #fdf6e3;
            }
            QHeaderView::section {
                background-color: #073642;
                color: #839496;
                border: 1px solid #586e75;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #586e75;
                background-color: #002b36;
            }
            QTabBar::tab {
                background-color: #073642;
                color: #839496;
                border: 1px solid #586e75;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #586e75;
            }
            QGroupBox {
                border: 1px solid #586e75;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #839496;
            }
        """
        self.setStyleSheet(solarized_stylesheet)
        print("Solarized Dark theme applied")

    # NEW THEME 5: GRUVBOX
    def set_gruvbox_theme(self):
        """Apply Gruvbox theme - retro groove color scheme"""
        gruvbox_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #282828;
                color: #ebdbb2;
            }
            QMenuBar {
                background-color: #3c3836;
                color: #ebdbb2;
            }
            QMenuBar::item:selected {
                background-color: #504945;
            }
            QMenu {
                background-color: #3c3836;
                color: #ebdbb2;
                border: 1px solid #665c54;
            }
            QMenu::item:selected {
                background-color: #fabd2f;
                color: #282828;
            }
            QPushButton {
                background-color: #3c3836;
                color: #ebdbb2;
                border: 1px solid #665c54;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #504945;
            }
            QPushButton:pressed {
                background-color: #fabd2f;
                color: #282828;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #3c3836;
                color: #ebdbb2;
                border: 1px solid #665c54;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #282828;
                color: #ebdbb2;
                border: 1px solid #665c54;
                alternate-background-color: #32302f;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #fabd2f;
                color: #282828;
            }
            QHeaderView::section {
                background-color: #3c3836;
                color: #ebdbb2;
                border: 1px solid #665c54;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #665c54;
                background-color: #282828;
            }
            QTabBar::tab {
                background-color: #3c3836;
                color: #ebdbb2;
                border: 1px solid #665c54;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #504945;
            }
            QGroupBox {
                border: 1px solid #665c54;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #ebdbb2;
            }
        """
        self.setStyleSheet(gruvbox_stylesheet)
        print("Gruvbox theme applied")

    # NEW THEME 6: ONE DARK
    def set_one_dark_theme(self):
        """Apply One Dark theme - inspired by Atom's default dark theme"""
        one_dark_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #282c34;
                color: #abb2bf;
            }
            QMenuBar {
                background-color: #21252b;
                color: #abb2bf;
            }
            QMenuBar::item:selected {
                background-color: #2c313a;
            }
            QMenu {
                background-color: #21252b;
                color: #abb2bf;
                border: 1px solid #181a1f;
            }
            QMenu::item:selected {
                background-color: #61afef;
                color: #282c34;
            }
            QPushButton {
                background-color: #21252b;
                color: #abb2bf;
                border: 1px solid #181a1f;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #2c313a;
            }
            QPushButton:pressed {
                background-color: #61afef;
                color: #282c34;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
                background-color: #21252b;
                color: #abb2bf;
                border: 1px solid #181a1f;
                padding: 3px;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #282c34;
                color: #abb2bf;
                border: 1px solid #181a1f;
                alternate-background-color: #2c313a;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #61afef;
                color: #282c34;
            }
            QHeaderView::section {
                background-color: #21252b;
                color: #abb2bf;
                border: 1px solid #181a1f;
                padding: 5px;
            }
            QTabWidget::pane {
                border: 1px solid #181a1f;
                background-color: #282c34;
            }
            QTabBar::tab {
                background-color: #21252b;
                color: #abb2bf;
                border: 1px solid #181a1f;
                padding: 5px 10px;
            }
            QTabBar::tab:selected {
                background-color: #2c313a;
            }
            QGroupBox {
                border: 1px solid #181a1f;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                color: #abb2bf;
            }
        """
        self.setStyleSheet(one_dark_stylesheet)
        print("One Dark theme applied")

    # NEW THEME 7: BRANDON'S HOTDOG STAND
    def set_hotdog_stand_theme(self):
        """Apply Brandon's Hotdog Stand theme - a loving tribute to Windows 3.1's worst color scheme.

        The original Hot Dog Stand theme was included in Windows 3.1 and is famous for being
        called 'the world's worst theme'. Legend has it, it was created as a challenge to
        come up with the worst scheme possible. Colors represent ketchup (red) and mustard (yellow).
        """
        # Classic Hot Dog Stand colors:
        # Red: #FF0000 (buttons, windows, borders)
        # Yellow: #FFFF00 (background, workspace)
        # Black: #000000 (active title, highlights)
        # White: #FFFFFF (text on red, menus)

        hotdog_stylesheet = """
            QMainWindow, QDialog, QWidget {
                background-color: #FFFF00;
                color: #FFFFFF;
            }
            QMenuBar {
                background-color: #FF0000;
                color: #FFFFFF;
                font-weight: bold;
            }
            QMenuBar::item:selected {
                background-color: #000000;
                color: #FFFFFF;
            }
            QMenu {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px solid #000000;
            }
            QMenu::item:selected {
                background-color: #FFFF00;
                color: #000000;
            }
            QPushButton {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px outset #FF0000;
                padding: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #CC0000;
            }
            QPushButton:pressed {
                background-color: #000000;
                color: #FFFFFF;
                border-style: inset;
            }
            QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px inset #000000;
                padding: 3px;
                selection-background-color: #FFFF00;
                selection-color: #000000;
            }
            QComboBox {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px outset #FF0000;
                padding: 3px;
            }
            QComboBox::drop-down {
                background-color: #FF0000;
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #FF0000;
                color: #FFFFFF;
                selection-background-color: #FFFF00;
                selection-color: #000000;
            }
            QTreeWidget, QListWidget, QTableWidget {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px inset #000000;
                alternate-background-color: #CC0000;
            }
            QTreeWidget::item:selected, QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #000000;
                color: #FFFFFF;
            }
            QTreeWidget::item:hover, QListWidget::item:hover, QTableWidget::item:hover {
                background-color: #CC0000;
                color: #FFFFFF;
            }
            QHeaderView::section {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px outset #FF0000;
                padding: 5px;
                font-weight: bold;
            }
            QTabWidget::pane {
                border: 2px solid #000000;
                background-color: #FF0000;
            }
            QTabBar::tab {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px outset #FF0000;
                padding: 5px 10px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #FFFF00;
                color: #FF0000;
                border-bottom: 2px solid #FFFF00;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #CC0000;
            }
            QGroupBox {
                border: 2px solid #000000;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #FF0000;
            }
            QGroupBox::title {
                color: #FFFFFF;
                font-weight: bold;
            }
            QScrollBar:vertical {
                background-color: #FFFF00;
                width: 16px;
                border: 1px solid #000000;
            }
            QScrollBar::handle:vertical {
                background-color: #FF0000;
                border: 2px outset #FF0000;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background-color: #FF0000;
                border: 2px outset #FF0000;
                height: 16px;
            }
            QScrollBar:horizontal {
                background-color: #FFFF00;
                height: 16px;
                border: 1px solid #000000;
            }
            QScrollBar::handle:horizontal {
                background-color: #FF0000;
                border: 2px outset #FF0000;
                min-width: 20px;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                background-color: #FF0000;
                border: 2px outset #FF0000;
                width: 16px;
            }
            QLabel {
                color: #FF0000;
                font-weight: bold;
            }
            QCheckBox {
                color: #FF0000;
                font-weight: bold;
            }
            QCheckBox::indicator {
                background-color: #FF0000;
                border: 2px inset #000000;
            }
            QCheckBox::indicator:checked {
                background-color: #FFFF00;
                border: 2px inset #000000;
            }
            QSlider::groove:horizontal {
                background-color: #FF0000;
                height: 8px;
                border: 1px solid #000000;
            }
            QSlider::handle:horizontal {
                background-color: #FFFF00;
                border: 2px outset #FF0000;
                width: 16px;
            }
            QSplitter::handle {
                background-color: #FF0000;
            }
            QStatusBar {
                background-color: #FF0000;
                color: #FFFFFF;
            }
            QToolTip {
                background-color: #FF0000;
                color: #FFFFFF;
                border: 2px solid #000000;
                font-weight: bold;
            }
            QMessageBox {
                background-color: #FF0000;
            }
            QMessageBox QLabel {
                color: #FFFFFF;
                font-weight: bold;
            }
        """
        self.setStyleSheet(hotdog_stylesheet)
        print("Brandon's Hotdog Stand theme applied - enjoy the ketchup and mustard!")

    def load_and_apply_theme(self):
        """Load saved theme and apply it"""
        from pathlib import Path
        import json
        
        config_file = Path.home() / '.nexus' / 'settings.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    settings = json.load(f)
                    theme = settings.get('theme', 'Dark')
                    self.apply_theme(theme)  # This now calls update_terminal_themes too
            except:
                self.set_dark_theme()
                self.update_terminal_themes("dark")
        else:
            self.set_dark_theme()
            self.update_terminal_themes("dark")

    def update_terminal_themes(self, theme):
        """Update theme for all terminal widgets"""
        # Update general terminal if it exists
        if hasattr(self, 'terminal') and hasattr(self.terminal, 'general_terminal'):
            if hasattr(self.terminal.general_terminal, 'terminal_output'):
                self.terminal.general_terminal.terminal_output.set_theme(theme)
        
        # Update all agent terminals
        if hasattr(self, 'terminal') and hasattr(self.terminal, 'agent_terminals'):
            for agent_guid, agent_terminal in self.terminal.agent_terminals.items():
                if hasattr(agent_terminal, 'terminal_output'):
                    agent_terminal.terminal_output.set_theme(theme)