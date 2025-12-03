# agent_table.py
# Table view for agents with sortable columns and multi-select support

from PyQt6.QtWidgets import (QTableWidget, QTableWidgetItem, QWidget, QVBoxLayout,
                              QHeaderView, QAbstractItemView, QMenu, QMessageBox,
                              QInputDialog, QApplication)
from PyQt6.QtCore import Qt, QTimer, QDateTime, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont
from utils.constants import AGENT_TREE_UPDATE_INTERVAL


class AgentTableWidget(QWidget):
    """Table view for agents with sortable columns and multi-select support"""

    # Signal emitted when agents are selected (list of GUIDs)
    agents_selected = pyqtSignal(list)
    # Signal emitted when a single agent is double-clicked
    agent_activated = pyqtSignal(str, str)  # name, guid
    # Signal emitted when agents are removed (for syncing other views)
    agents_removed = pyqtSignal(list)  # list of GUIDs that were removed

    # Column definitions (no Parent column - hierarchy shown via indentation)
    COLUMNS = [
        ('Name', 180),
        ('Hostname', 120),
        ('Username', 100),
        ('IP', 120),
        ('OS', 80),
        ('Arch', 50),
        ('Protocol', 70),
        ('PID', 60),
        ('Last Seen', 100),
        ('Tags', 100),
    ]

    def __init__(self, terminal_widget=None, agent_tree_widget=None):
        super().__init__()
        self.terminal_widget = terminal_widget
        self.agent_tree_widget = agent_tree_widget  # Reference to share data

        self.setup_ui()
        self.setup_timer()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])

        # Set column widths
        header = self.table.horizontalHeader()
        for i, (_, width) in enumerate(self.COLUMNS):
            self.table.setColumnWidth(i, width)
        header.setStretchLastSection(True)

        # Enable sorting
        self.table.setSortingEnabled(True)

        # Enable multi-select
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)

        # Enable alternating row colors
        self.table.setAlternatingRowColors(True)

        # Context menu for table rows
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        # Context menu for header (to reset hierarchy)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        header.customContextMenuRequested.connect(self.show_header_context_menu)

        # Connect signals
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.table.itemClicked.connect(self.on_item_clicked)

        # Track when user sorts manually (to show hint about resetting)
        header.sectionClicked.connect(self.on_header_clicked)
        self.is_sorted_manually = False

        # Style the table
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: #d4d4d4;
                gridline-color: #3a3a3a;
                border: none;
            }
            QTableWidget::item {
                padding: 4px;
                border-bottom: 1px solid #3a3a3a;
            }
            QTableWidget::item:selected {
                background-color: #094771;
                color: white;
            }
            QTableWidget::item:hover {
                background-color: #3a3a3a;
            }
            QHeaderView::section {
                background-color: #333333;
                color: #d4d4d4;
                padding: 6px;
                border: none;
                border-bottom: 2px solid #094771;
                font-weight: bold;
            }
            QHeaderView::section:hover {
                background-color: #404040;
            }
        """)

        layout.addWidget(self.table)
        self.setLayout(layout)

    def setup_timer(self):
        """Setup timer for updating last seen timestamps"""
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_last_seen)
        self.update_timer.start(AGENT_TREE_UPDATE_INTERVAL)

    def refresh_from_tree(self):
        """Refresh table data from the agent tree widget with hierarchical ordering"""
        if not self.agent_tree_widget:
            return

        # Temporarily disable sorting to maintain hierarchy
        self.table.setSortingEnabled(False)

        # Clear and rebuild
        self.table.setRowCount(0)

        # Get all non-deleted agents
        all_agents = [a for a in self.agent_tree_widget.agent_data
                      if not a.get('deleted') or self.agent_tree_widget.show_deleted]

        # Build a map of parent -> children for quick lookup
        agent_guids = {a['guid'] for a in all_agents}
        children_map = {}  # parent_guid -> [child_agents]
        root_agents = []

        for agent in all_agents:
            parent_id = agent.get('parent_client_id', '')
            if not parent_id or parent_id not in agent_guids:
                # This is a root agent (no parent or parent not in our list)
                root_agents.append(agent)
            else:
                # This is a child agent
                if parent_id not in children_map:
                    children_map[parent_id] = []
                children_map[parent_id].append(agent)

        # Recursively build the display list with proper ordering
        def add_agent_with_children(agent, depth):
            """Add an agent and then immediately add all its children (depth-first)"""
            result = [(agent, depth)]
            # Get children of this agent and add them recursively
            children = children_map.get(agent['guid'], [])
            for child in children:
                result.extend(add_agent_with_children(child, depth + 1))
            return result

        # Build the final ordered list
        agents_to_display = []
        for root in root_agents:
            agents_to_display.extend(add_agent_with_children(root, 0))

        # Add rows in hierarchical order
        for agent, depth in agents_to_display:
            self.add_agent_row(agent, depth)

        # Keep sorting disabled to maintain hierarchy
        # User can still click headers to sort, but it will flatten the view
        self.table.setSortingEnabled(True)

    def add_agent_row(self, agent, depth=0):
        """Add a single agent row to the table with optional indentation for hierarchy"""
        row = self.table.rowCount()
        self.table.insertRow(row)

        guid = agent.get('guid', '')
        link_type = agent.get('link_type', '')

        # Get display name (alias or short GUID)
        if self.agent_tree_widget:
            alias = self.agent_tree_widget.agent_aliases.get(guid, '')
            display_name = alias if alias else f"{guid[:16]}..."
        else:
            display_name = f"{guid[:16]}..."

        # Add visual hierarchy indicator based on depth
        if depth > 0:
            # Indent with spaces and arrow for child agents
            indent = "    " * (depth - 1)  # Extra indent for deeper nesting
            display_name = f"{indent}↳ [{link_type.upper()}] {display_name}"

        # Column data (no Parent column - hierarchy shown in Name)
        columns_data = [
            display_name,
            agent.get('hostname', 'N/A'),
            agent.get('username', 'N/A'),
            agent.get('ip', 'N/A'),
            agent.get('os', 'N/A'),
            self._extract_arch(agent),
            agent.get('protocol', 'N/A'),
            self._extract_pid(agent),
            self._format_last_seen(agent),
            self._format_tags(agent),
        ]

        for col, data in enumerate(columns_data):
            item = QTableWidgetItem(str(data))
            item.setData(Qt.ItemDataRole.UserRole, guid)  # Store GUID in each cell

            # Make cells non-editable
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            # Color coding for OS
            if col == 4:  # OS column
                os_name = str(data).lower()
                if 'windows' in os_name:
                    item.setForeground(QBrush(QColor('#6bcf7f')))  # Green for Windows
                elif 'linux' in os_name:
                    item.setForeground(QBrush(QColor('#ffd93d')))  # Yellow for Linux
                elif 'darwin' in os_name or 'mac' in os_name:
                    item.setForeground(QBrush(QColor('#4dabf7')))  # Blue for macOS

            # Color coding for linked agents (Name column) - different colors for link types
            if col == 0 and depth > 0:
                if 'smb' in link_type.lower():
                    item.setForeground(QBrush(QColor('#FF5722')))  # Orange for SMB
                elif 'tcp' in link_type.lower():
                    item.setForeground(QBrush(QColor('#2196F3')))  # Blue for TCP
                else:
                    item.setForeground(QBrush(QColor('#9ca3af')))  # Gray for other

            self.table.setItem(row, col, item)

        # Gray out deleted agents
        if agent.get('deleted'):
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    item.setForeground(QBrush(QColor('#666666')))

    def _extract_arch(self, agent):
        """Extract architecture from agent details"""
        for detail in agent.get('details', []):
            if detail.startswith('Architecture:'):
                return detail.split(':', 1)[1].strip()
        return 'N/A'

    def _extract_pid(self, agent):
        """Extract PID from agent details"""
        for detail in agent.get('details', []):
            if detail.startswith('PID:'):
                return detail.split(':', 1)[1].strip()
        return 'N/A'

    def _format_last_seen(self, agent):
        """Format last seen timestamp"""
        last_seen = agent.get('last_seen_timestamp')
        if not last_seen:
            return 'N/A'

        current_time = QDateTime.currentDateTime()
        seconds = last_seen.secsTo(current_time)

        if seconds < 60:
            return f'{seconds}s ago'
        elif seconds < 3600:
            minutes = seconds // 60
            return f'{minutes}m ago'
        elif seconds < 86400:
            hours = seconds // 3600
            return f'{hours}h ago'
        else:
            days = seconds // 86400
            return f'{days}d ago'

    def _format_tags(self, agent):
        """Format tags for display"""
        if not self.agent_tree_widget:
            return ''
        guid = agent.get('guid', '')
        tags = self.agent_tree_widget.agent_tags.get(guid, [])
        if tags:
            return ', '.join([tag['name'] for tag in tags])
        return ''

    def update_last_seen(self):
        """Update last seen column for all agents"""
        if not self.agent_tree_widget:
            return

        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 0)
            if not name_item:
                continue

            guid = name_item.data(Qt.ItemDataRole.UserRole)
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent:
                last_seen_item = self.table.item(row, 8)  # Last Seen column
                if last_seen_item:
                    new_text = self._format_last_seen(agent)
                    if last_seen_item.text() != new_text:
                        last_seen_item.setText(new_text)

    def on_selection_changed(self):
        """Handle selection change - emit selected agent GUIDs"""
        selected_guids = self.get_selected_agent_guids()
        self.agents_selected.emit(selected_guids)

    def on_header_clicked(self, logical_index):
        """Track when user manually sorts by clicking a column header"""
        self.is_sorted_manually = True

    def show_header_context_menu(self, position):
        """Show context menu for table header with reset option"""
        menu = QMenu(self)

        reset_action = menu.addAction("Reset to Hierarchy")
        reset_action.setToolTip("Restore parent-child ordering (parents followed by their linked agents)")

        action = menu.exec(self.table.horizontalHeader().mapToGlobal(position))

        if action == reset_action:
            self.reset_to_hierarchy()

    def reset_to_hierarchy(self):
        """Reset table to hierarchical ordering (parents followed by children)"""
        self.is_sorted_manually = False
        # Disable sorting and clear any active sort indicator
        self.table.setSortingEnabled(False)
        # Clear the sort indicator by setting to an invalid column (-1)
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        # Refresh to restore hierarchy
        self.refresh_from_tree()
        # Re-enable sorting for future user interaction
        self.table.setSortingEnabled(True)

    def on_item_clicked(self, item):
        """Handle single click - open terminal for the clicked agent (matches tree view behavior)"""
        # Get the GUID from the clicked item
        guid = item.data(Qt.ItemDataRole.UserRole)
        if not guid:
            return

        # Open terminal for this agent
        if self.agent_tree_widget and self.terminal_widget:
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent:
                self.agent_activated.emit(agent['name'], guid)
                self.terminal_widget.add_agent_tab(agent['name'], guid)

    def on_item_double_clicked(self, item):
        """Handle double-click to open agent terminal"""
        guid = item.data(Qt.ItemDataRole.UserRole)
        if guid and self.agent_tree_widget:
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent:
                self.agent_activated.emit(agent['name'], guid)
                if self.terminal_widget:
                    self.terminal_widget.add_agent_tab(agent['name'], guid)

    def get_selected_agent_guids(self):
        """Get list of selected agent GUIDs"""
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())

        guids = []
        for row in selected_rows:
            item = self.table.item(row, 0)
            if item:
                guid = item.data(Qt.ItemDataRole.UserRole)
                if guid:
                    guids.append(guid)
        return guids

    def get_selected_agents(self):
        """Get list of selected agent data dictionaries"""
        guids = self.get_selected_agent_guids()
        agents = []
        if self.agent_tree_widget:
            for guid in guids:
                agent = self.agent_tree_widget.agent_by_guid.get(guid)
                if agent:
                    agents.append(agent)
        return agents

    def show_context_menu(self, position):
        """Show context menu for selected agents"""
        selected_guids = self.get_selected_agent_guids()

        if not selected_guids:
            return

        menu = QMenu(self)

        # Single agent actions
        if len(selected_guids) == 1:
            guid = selected_guids[0]

            open_terminal_action = menu.addAction("Open Terminal")
            copy_guid_action = menu.addAction("Copy GUID")
            menu.addSeparator()
            rename_action = menu.addAction("Rename Agent")
            manage_tags_action = menu.addAction("Manage Tags...")
            menu.addSeparator()
            remove_action = menu.addAction("Remove Agent")

            action = menu.exec(self.table.viewport().mapToGlobal(position))

            if action == open_terminal_action:
                self.open_agent_terminal(guid)
            elif action == copy_guid_action:
                self.copy_guid_to_clipboard(guid)
            elif action == rename_action:
                self.rename_agent(guid)
            elif action == manage_tags_action:
                self.manage_agent_tags(guid)
            elif action == remove_action:
                self.remove_agents([guid])
        else:
            # Multi-agent actions
            count = len(selected_guids)

            open_all_action = menu.addAction(f"Open {count} Terminals")
            menu.addSeparator()
            remove_all_action = menu.addAction(f"Remove {count} Agents")

            action = menu.exec(self.table.viewport().mapToGlobal(position))

            if action == open_all_action:
                for guid in selected_guids:
                    self.open_agent_terminal(guid)
            elif action == remove_all_action:
                self.remove_agents(selected_guids)

    def open_agent_terminal(self, guid):
        """Open terminal for an agent"""
        if self.agent_tree_widget and self.terminal_widget:
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent:
                self.terminal_widget.add_agent_tab(agent['name'], guid)

    def copy_guid_to_clipboard(self, guid):
        """Copy GUID to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(guid)

    def rename_agent(self, guid):
        """Rename an agent - delegates to tree widget"""
        if self.agent_tree_widget:
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent and agent['name'] in self.agent_tree_widget.agent_items:
                item = self.agent_tree_widget.agent_items[agent['name']]
                self.agent_tree_widget.rename_agent(item)
                # Refresh table to show new name
                self.refresh_from_tree()

    def manage_agent_tags(self, guid):
        """Manage tags for an agent - delegates to tree widget"""
        if self.agent_tree_widget:
            agent = self.agent_tree_widget.agent_by_guid.get(guid)
            if agent and agent['name'] in self.agent_tree_widget.agent_items:
                item = self.agent_tree_widget.agent_items[agent['name']]
                self.agent_tree_widget.manage_agent_tags(item)
                # Refresh table to show new tags
                self.refresh_from_tree()

    def remove_agents(self, guids):
        """Remove multiple agents"""
        if not self.agent_tree_widget:
            return

        count = len(guids)
        msg = f"Are you sure you want to remove {count} agent(s)?"

        reply = QMessageBox.question(
            self, 'Remove Agents', msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            removed_guids = []
            for guid in guids:
                agent = self.agent_tree_widget.agent_by_guid.get(guid)
                if agent:
                    # Remove agent (sends to server and marks as deleted)
                    if self._remove_agent_no_confirm(guid):
                        removed_guids.append(guid)

            # Refresh table
            self.refresh_from_tree()

            # Emit signal to notify other views
            if removed_guids:
                self.agents_removed.emit(removed_guids)

    def _remove_agent_no_confirm(self, guid):
        """Remove agent without confirmation (used for batch removal). Returns True on success."""
        if not self.agent_tree_widget:
            return False

        agent = self.agent_tree_widget.agent_by_guid.get(guid)
        if not agent:
            return False

        ws_thread = self.agent_tree_widget.ws_thread
        if not ws_thread or not ws_thread.is_connected():
            return False

        import json
        import asyncio

        msg = {
            "type": "remove_agent",
            "data": {
                "agent_id": guid,
                "username": ws_thread.username
            }
        }

        try:
            asyncio.run_coroutine_threadsafe(
                ws_thread.ws_client.send_message(json.dumps(msg)),
                ws_thread.loop
            )
            agent['deleted'] = True
            if agent['name'] in self.agent_tree_widget.agent_items:
                self.agent_tree_widget.agent_items[agent['name']].setHidden(True)
            return True
        except Exception as e:
            print(f"Failed to remove agent {guid}: {e}")
            return False

    def select_all(self):
        """Select all agents"""
        self.table.selectAll()

    def clear_selection(self):
        """Clear selection"""
        self.table.clearSelection()

    def filter_agents(self, filter_text):
        """Filter agents based on search text"""
        filter_lower = filter_text.lower().strip()

        for row in range(self.table.rowCount()):
            show_row = False

            if not filter_lower:
                show_row = True
            else:
                # Check all columns for match
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and filter_lower in item.text().lower():
                        show_row = True
                        break

                # Also check GUID
                name_item = self.table.item(row, 0)
                if name_item:
                    guid = name_item.data(Qt.ItemDataRole.UserRole)
                    if guid and filter_lower in guid.lower():
                        show_row = True

            self.table.setRowHidden(row, not show_row)
