# agent_display.py
# Unified agent display widget with tree, table, and graph views
# Supports multi-select across all view modes

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
                              QPushButton, QButtonGroup, QLabel, QLineEdit,
                              QFrame, QSizePolicy, QMenu, QMessageBox)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QIcon

from .agent_tree import AgentTreeWidget
from .agent_table import AgentTableWidget
from .session_graph import SessionGraphWidget


class ViewToggleButton(QPushButton):
    """Styled toggle button for view switching"""

    def __init__(self, text, icon_char=None):
        super().__init__(text)
        self.setCheckable(True)
        self.setMinimumWidth(70)
        self.setStyleSheet("""
            QPushButton {
                background-color: #333333;
                color: #888888;
                border: none;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:checked {
                background-color: #094771;
                color: white;
            }
            QPushButton:hover:!checked {
                background-color: #404040;
                color: #d4d4d4;
            }
        """)


class AgentDisplayWidget(QWidget):
    """
    Unified agent display widget that provides three views:
    - Tree view (hierarchical, shows linked agents as children)
    - Table view (sortable columns, better for many agents)
    - Graph view (visual network diagram showing connections)

    All views share the same data and support multi-select with synchronized selection.
    """

    # Signals
    agents_selected = pyqtSignal(list)  # List of selected agent GUIDs
    agent_activated = pyqtSignal(str, str)  # name, guid - when double-clicked

    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget

        # Track selected agents across views
        self.selected_guids = []

        self.setup_ui()
        self.setup_connections()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar with search and view toggle
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #2b2b2b;
                border-bottom: 1px solid #3a3a3a;
            }
        """)
        header_layout = QVBoxLayout()
        header_layout.setContentsMargins(8, 8, 8, 8)
        header_layout.setSpacing(8)

        # Top row: Search and view toggle
        top_row = QHBoxLayout()

        # Search bar
        search_layout = QHBoxLayout()
        search_label = QLabel("Filter:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search agents (name, GUID, OS, hostname, tags...)")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self.filter_agents)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        top_row.addLayout(search_layout, stretch=1)

        top_row.addSpacing(20)

        # View toggle buttons
        view_toggle_layout = QHBoxLayout()
        view_toggle_layout.setSpacing(0)

        self.view_button_group = QButtonGroup(self)
        self.view_button_group.setExclusive(True)

        self.tree_btn = ViewToggleButton("Tree")
        self.tree_btn.setChecked(True)
        self.view_button_group.addButton(self.tree_btn, 0)
        view_toggle_layout.addWidget(self.tree_btn)

        self.table_btn = ViewToggleButton("Table")
        self.view_button_group.addButton(self.table_btn, 1)
        view_toggle_layout.addWidget(self.table_btn)

        self.graph_btn = ViewToggleButton("Graph")
        self.view_button_group.addButton(self.graph_btn, 2)
        view_toggle_layout.addWidget(self.graph_btn)

        top_row.addLayout(view_toggle_layout)
        header_layout.addLayout(top_row)

        # Selection info bar (shown when multiple agents selected)
        self.selection_bar = QFrame()
        self.selection_bar.setStyleSheet("""
            QFrame {
                background-color: #094771;
                border-radius: 4px;
                padding: 4px;
            }
        """)
        self.selection_bar.setVisible(False)

        selection_layout = QHBoxLayout()
        selection_layout.setContentsMargins(8, 4, 8, 4)

        self.selection_label = QLabel("0 agents selected")
        self.selection_label.setStyleSheet("color: white; font-weight: bold;")
        selection_layout.addWidget(self.selection_label)

        selection_layout.addStretch()

        # Batch action buttons
        self.open_all_btn = QPushButton("Open Terminals")
        self.open_all_btn.clicked.connect(self.open_selected_terminals)
        self.open_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #2ecc71;
                color: white;
                border: none;
                padding: 4px 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #27ae60;
            }
        """)
        selection_layout.addWidget(self.open_all_btn)

        self.clear_selection_btn = QPushButton("Clear")
        self.clear_selection_btn.clicked.connect(self.clear_selection)
        self.clear_selection_btn.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                padding: 4px 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        selection_layout.addWidget(self.clear_selection_btn)

        self.selection_bar.setLayout(selection_layout)
        header_layout.addWidget(self.selection_bar)

        header.setLayout(header_layout)
        layout.addWidget(header)

        # Stacked widget for different views
        self.stack = QStackedWidget()

        # Tree view (original AgentTreeWidget, slightly modified)
        self.tree_widget = AgentTreeWidget(self.terminal_widget)
        # Hide the tree's own search bar since we have a unified one
        self.tree_widget.search_input.setVisible(False)
        self.tree_widget.layout().itemAt(0).layout().itemAt(0).widget().setVisible(False)  # Hide label too

        # Enable multi-select on tree
        self.tree_widget.tree.setSelectionMode(
            self.tree_widget.tree.SelectionMode.ExtendedSelection
        )
        self.stack.addWidget(self.tree_widget)

        # Table view
        self.table_widget = AgentTableWidget(self.terminal_widget, self.tree_widget)
        self.stack.addWidget(self.table_widget)

        # Graph view
        self.graph_widget = SessionGraphWidget(self.terminal_widget, self.tree_widget)
        self.stack.addWidget(self.graph_widget)

        layout.addWidget(self.stack)

        self.setLayout(layout)

    def setup_connections(self):
        """Setup signal connections between components"""
        # View toggle
        self.view_button_group.idClicked.connect(self.switch_view)

        # Tree selection
        self.tree_widget.tree.itemSelectionChanged.connect(self.on_tree_selection_changed)

        # Table selection and actions
        self.table_widget.agents_selected.connect(self.on_table_selection_changed)
        self.table_widget.agent_activated.connect(self.on_agent_activated)
        self.table_widget.agents_removed.connect(self.on_agents_removed)

        # Graph selection
        self.graph_widget.agents_selected.connect(self.on_graph_selection_changed)
        self.graph_widget.agent_activated.connect(self.on_agent_activated)

    def switch_view(self, view_id):
        """Switch between tree (0), table (1), and graph (2) views"""
        self.stack.setCurrentIndex(view_id)

        # Refresh the view being switched to
        if view_id == 1:  # Table
            self.table_widget.refresh_from_tree()
            # Restore selection
            if self.selected_guids:
                self._select_in_table(self.selected_guids)
        elif view_id == 2:  # Graph
            self.graph_widget.refresh_graph()
            # Restore selection
            if self.selected_guids:
                self.graph_widget.select_agents(self.selected_guids)

        # Apply current filter
        self.filter_agents(self.search_input.text())

    def filter_agents(self, filter_text):
        """Apply filter across all views"""
        current_view = self.stack.currentIndex()

        if current_view == 0:  # Tree
            self.tree_widget.filter_agents(filter_text)
        elif current_view == 1:  # Table
            self.table_widget.filter_agents(filter_text)
        # Graph doesn't have filter (visual layout would break)

    def on_tree_selection_changed(self):
        """Handle selection change in tree view"""
        selected_items = self.tree_widget.tree.selectedItems()
        guids = []

        for item in selected_items:
            guid = item.data(0, Qt.ItemDataRole.UserRole)
            if guid:
                guids.append(guid)

        self.update_selection(guids, source='tree')

    def on_table_selection_changed(self, guids):
        """Handle selection change in table view"""
        self.update_selection(guids, source='table')

    def on_graph_selection_changed(self, guids):
        """Handle selection change in graph view"""
        self.update_selection(guids, source='graph')

    def update_selection(self, guids, source=None):
        """Update selection across all views"""
        self.selected_guids = guids

        # Update selection bar
        count = len(guids)
        if count > 1:
            self.selection_bar.setVisible(True)
            self.selection_label.setText(f"{count} agents selected")
        else:
            self.selection_bar.setVisible(False)

        # Sync selection to other views (if they're not the source)
        if source != 'tree':
            self._select_in_tree(guids)
        if source != 'table':
            self._select_in_table(guids)
        if source != 'graph':
            self.graph_widget.select_agents(guids)

        # Emit signal
        self.agents_selected.emit(guids)

    def _select_in_tree(self, guids):
        """Select agents in tree view"""
        self.tree_widget.tree.blockSignals(True)
        self.tree_widget.tree.clearSelection()

        for guid in guids:
            agent = self.tree_widget.agent_by_guid.get(guid)
            if agent and agent['name'] in self.tree_widget.agent_items:
                item = self.tree_widget.agent_items[agent['name']]
                item.setSelected(True)

        self.tree_widget.tree.blockSignals(False)

    def _select_in_table(self, guids):
        """Select agents in table view"""
        self.table_widget.table.blockSignals(True)
        self.table_widget.table.clearSelection()

        for row in range(self.table_widget.table.rowCount()):
            item = self.table_widget.table.item(row, 0)
            if item:
                row_guid = item.data(Qt.ItemDataRole.UserRole)
                if row_guid in guids:
                    self.table_widget.table.selectRow(row)

        self.table_widget.table.blockSignals(False)

    def on_agent_activated(self, name, guid):
        """Handle agent double-click activation"""
        self.agent_activated.emit(name, guid)
        if self.terminal_widget:
            self.terminal_widget.add_agent_tab(name, guid)

    def on_agents_removed(self, guids):
        """Handle agents being removed - sync all views"""
        # Remove from selection if any removed agents were selected
        self.selected_guids = [g for g in self.selected_guids if g not in guids]

        # Update selection bar
        count = len(self.selected_guids)
        if count > 1:
            self.selection_label.setText(f"{count} agents selected")
        else:
            self.selection_bar.setVisible(False)

        # Refresh graph view (table already refreshed itself, tree already hidden items)
        self.graph_widget.refresh_graph()

        # Log the removal
        if self.terminal_widget:
            for guid in guids:
                self.terminal_widget.log_message(f"Agent {guid[:8]}... removed")

    def open_selected_terminals(self):
        """Open terminals for all selected agents"""
        if not self.terminal_widget:
            return

        for guid in self.selected_guids:
            agent = self.tree_widget.agent_by_guid.get(guid)
            if agent:
                self.terminal_widget.add_agent_tab(agent['name'], guid)

    def clear_selection(self):
        """Clear selection in all views"""
        self.update_selection([], source=None)

    def get_selected_agents(self):
        """Get list of selected agent data dictionaries"""
        agents = []
        for guid in self.selected_guids:
            agent = self.tree_widget.agent_by_guid.get(guid)
            if agent:
                agents.append(agent)
        return agents

    def get_selected_guids(self):
        """Get list of selected agent GUIDs"""
        return self.selected_guids.copy()

    # Delegate methods to tree widget for compatibility
    @property
    def agent_data(self):
        return self.tree_widget.agent_data

    @property
    def listener_data(self):
        return self.tree_widget.listener_data

    @property
    def agent_by_guid(self):
        return self.tree_widget.agent_by_guid

    @property
    def agent_aliases(self):
        return self.tree_widget.agent_aliases

    @property
    def agent_tags(self):
        return self.tree_widget.agent_tags

    @property
    def ws_thread(self):
        return self.tree_widget.ws_thread

    @ws_thread.setter
    def ws_thread(self, value):
        self.tree_widget.ws_thread = value

    @property
    def current_view(self):
        return self.tree_widget.current_view

    def show_agents(self):
        self.tree_widget.show_agents()
        # Refresh other views if they're visible
        if self.stack.currentIndex() == 1:
            self.table_widget.refresh_from_tree()
        elif self.stack.currentIndex() == 2:
            self.graph_widget.refresh_graph()

    def show_listeners(self):
        self.tree_widget.show_listeners()

    def handle_new_connection(self, conn_data):
        self.tree_widget.handle_new_connection(conn_data)
        # Refresh active view
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def add_listener(self, *args, **kwargs):
        return self.tree_widget.add_listener(*args, **kwargs)

    def remove_listener(self, *args, **kwargs):
        return self.tree_widget.remove_listener(*args, **kwargs)

    def get_listener_names(self):
        return self.tree_widget.get_listener_names()

    def loadStateFromDatabase(self):
        self.tree_widget.loadStateFromDatabase()
        # Refresh active view after a short delay
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def handle_agent_deleted(self, data):
        self.tree_widget.handle_agent_deleted(data)
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def handle_agent_checkin(self, *args, **kwargs):
        self.tree_widget.handle_agent_checkin(*args, **kwargs)

    def handle_agent_renamed(self, data):
        self.tree_widget.handle_agent_renamed(data)
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def handle_agent_tags_updated(self, data):
        self.tree_widget.handle_agent_tags_updated(data)
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)

    def handle_link_update(self, data):
        self.tree_widget.handle_link_update(data)
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def handle_agent_reactivation(self, conn_data):
        self.tree_widget.handle_agent_reactivation(conn_data)
        if self.stack.currentIndex() == 1:
            QTimer.singleShot(100, self.table_widget.refresh_from_tree)
        elif self.stack.currentIndex() == 2:
            QTimer.singleShot(100, self.graph_widget.refresh_graph)

    def update_existing_connection(self, *args, **kwargs):
        self.tree_widget.update_existing_connection(*args, **kwargs)

    def get_agent_by_guid(self, guid):
        return self.tree_widget.get_agent_by_guid(guid)

    def cleanup(self):
        """Cleanup resources"""
        self.tree_widget.cleanup()
