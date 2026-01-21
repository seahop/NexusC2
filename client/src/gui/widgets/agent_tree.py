#agent_tree.py
from PyQt6.QtWidgets import (QTreeWidget, QTreeWidgetItem, QWidget, QVBoxLayout,
                              QMessageBox, QMenu, QInputDialog, QLineEdit, QHBoxLayout, QLabel)
from PyQt6.QtCore import QTimer, QDateTime, Qt, pyqtSlot, pyqtSignal, QThread
from PyQt6.QtWidgets import QApplication
import json
import asyncio
import sqlite3
import traceback
from utils.constants import AGENT_TREE_UPDATE_INTERVAL

class AgentTreeWidget(QWidget):
    # Signal emitted when agents are removed (for syncing other views)
    agents_removed = pyqtSignal(list)  # list of GUIDs that were removed

    # Signals for thread-safe operations (called from websocket thread)
    _agent_renamed_signal = pyqtSignal(dict)
    _agent_tags_updated_signal = pyqtSignal(dict)
    _new_connection_signal = pyqtSignal(dict)
    _update_connection_signal = pyqtSignal(dict)

    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget
        layout = QVBoxLayout()
        self.is_state_loaded = False

        # Connect thread-safe signals to their implementations
        self._agent_renamed_signal.connect(self._do_handle_agent_renamed, Qt.ConnectionType.QueuedConnection)
        self._agent_tags_updated_signal.connect(self._do_handle_agent_tags_updated, Qt.ConnectionType.QueuedConnection)
        self._new_connection_signal.connect(self._do_handle_new_connection, Qt.ConnectionType.QueuedConnection)
        self._update_connection_signal.connect(self._do_update_existing_connection, Qt.ConnectionType.QueuedConnection)

        # Add search bar at the top
        search_layout = QHBoxLayout()
        search_label = QLabel("Filter:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search agents (name, GUID, OS, hostname...)")
        self.search_input.textChanged.connect(self.filter_agents)
        self.search_input.setClearButtonEnabled(True)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(['Agents'])
        self.tree.itemClicked.connect(self.on_item_clicked)
        # Enable multi-selection with Ctrl+Click and Shift+Click
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        layout.addWidget(self.tree)
        self.show_deleted = False

        # Track current filter
        self.current_filter = ""

        # Store data and tree items
        self.agent_data = []
        self.listener_data = []
        self.agent_items = {}  # Store references to tree items
        self.last_seen_items = {}  # Cache "Last Seen" child items for O(1) lookup
        self.agent_by_guid = {}  # GUID-indexed dictionary for O(1) agent lookup

        # Setup timer for updating "Last Seen" timestamps
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_last_seen)
        self.update_timer.start(AGENT_TREE_UPDATE_INTERVAL)
        self._timer_active = True  # Track timer state

        self.setLayout(layout)
        self.current_view = 'agents'

        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.ws_thread = None  # We'll set this from the main window
        self.agent_aliases = {}
        self.agent_tags = {}  # GUID -> [{"name": "tag", "color": "#fff"}]

        # Load GUID display length from settings (default to 16)
        self.guid_display_length = self._load_guid_display_length()

    def _load_guid_display_length(self):
        """Load GUID display length from settings."""
        from pathlib import Path
        config_file = Path.home() / '.nexus' / 'settings.json'
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    settings = json.load(f)
                    return settings.get('guid_display_length', 16)
            except:
                pass
        return 16

    def keyPressEvent(self, event):
        """Handle keyboard shortcuts"""
        # Ctrl+F to focus search
        if event.key() == Qt.Key.Key_F and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
            self.search_input.setFocus()
            self.search_input.selectAll()
            event.accept()
        # Escape to clear search
        elif event.key() == Qt.Key.Key_Escape:
            if self.search_input.text():
                self.search_input.clear()
                event.accept()
            else:
                super().keyPressEvent(event)
        else:
            super().keyPressEvent(event) 
        
    def __del__(self):
        """Destructor to ensure timer is stopped"""
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()

    def showEvent(self, event):
        """Handle widget becoming visible - resume timer"""
        super().showEvent(event)
        if hasattr(self, 'update_timer') and hasattr(self, '_timer_active'):
            if not self._timer_active:
                self.update_timer.start(AGENT_TREE_UPDATE_INTERVAL)
                self._timer_active = True
                print("AgentTreeWidget: Timer resumed (widget visible)")

    def hideEvent(self, event):
        """Handle widget becoming hidden - pause timer"""
        super().hideEvent(event)
        if hasattr(self, 'update_timer') and hasattr(self, '_timer_active'):
            if self._timer_active:
                self.update_timer.stop()
                self._timer_active = False
                print("AgentTreeWidget: Timer paused (widget hidden)")

    def cleanup(self):
        """Explicit cleanup method for timers and resources"""
        if hasattr(self, 'update_timer'):
            self.update_timer.stop()
            self._timer_active = False
            print("AgentTreeWidget: Explicit cleanup - timer stopped")

    def filter_agents(self, filter_text):
        """Filter agents based on search text with fuzzy matching"""
        self.current_filter = filter_text.lower().strip()

        # If no filter, show all agents
        if not self.current_filter:
            for agent_name, tree_item in self.agent_items.items():
                tree_item.setHidden(False)
            return

        # Apply filter to each agent
        for agent_name, tree_item in self.agent_items.items():
            # Get agent data for this tree item
            agent = self.agent_by_guid.get(tree_item.data(0, Qt.ItemDataRole.UserRole))
            if not agent:
                # Fallback: try to match by name
                agent = next((a for a in self.agent_data if a['name'] == agent_name), None)

            if agent:
                # Build searchable text from all agent fields
                searchable_fields = [
                    agent.get('name', ''),
                    agent.get('guid', ''),
                    agent.get('hostname', ''),
                    agent.get('os', ''),
                    agent.get('username', ''),
                    agent.get('ip', ''),
                    self.agent_aliases.get(agent.get('guid', ''), '')  # Include alias
                ]

                # Include tags in search
                agent_guid = agent.get('guid', '')
                if agent_guid in self.agent_tags:
                    tag_names = [tag['name'] for tag in self.agent_tags[agent_guid]]
                    searchable_fields.extend(tag_names)

                searchable_text = ' '.join(str(f).lower() for f in searchable_fields if f)

                # Simple substring match (can be enhanced with fuzzy matching later)
                if self.current_filter in searchable_text:
                    tree_item.setHidden(False)
                else:
                    tree_item.setHidden(True)
            else:
                # If we can't find agent data, hide by default when filtering
                tree_item.setHidden(True)

    def update_last_seen(self):
        """Optimized last-seen update using cached child items."""
        if self.current_view != 'agents':
            return

        current_time = QDateTime.currentDateTime()

        # Only update visible, expanded, non-deleted agents
        for agent in self.agent_data:
            if agent.get('deleted'):
                continue

            agent_name = agent['name']
            if agent_name not in self.agent_items:
                continue

            tree_item = self.agent_items[agent_name]

            # Skip if item is not expanded (user can't see the Last Seen anyway)
            if not tree_item.isExpanded():
                continue

            last_seen_time = agent.get('last_seen_timestamp')
            if not last_seen_time:
                continue

            seconds = last_seen_time.secsTo(current_time)

            # Use cached "Last Seen" child item for O(1) access
            if agent_name in self.last_seen_items:
                child = self.last_seen_items[agent_name]
            else:
                # Cache miss - find and cache it
                child = None
                for i in range(tree_item.childCount()):
                    c = tree_item.child(i)
                    if c.text(0).startswith('Last Seen:'):
                        child = c
                        self.last_seen_items[agent_name] = child
                        break
                if not child:
                    continue

            # Update text (only if changed to avoid unnecessary redraws)
            if seconds < 60:
                new_text = f'Last Seen: {seconds} seconds ago'
            elif seconds < 3600:
                minutes = seconds // 60
                remaining_seconds = seconds % 60
                new_text = f'Last Seen: {minutes}m {remaining_seconds}s ago'
            elif seconds < 86400:
                hours = seconds // 3600
                minutes = (seconds % 3600) // 60
                new_text = f'Last Seen: {hours}h {minutes}m ago'
            else:
                days = seconds // 86400
                hours = (seconds % 86400) // 3600
                new_text = f'Last Seen: {days}d {hours}h ago'

            # Only update if text actually changed
            if child.text(0) != new_text:
                child.setText(0, new_text)

    def handle_new_connection(self, conn_data):
        """Thread-safe handler for new connection or reactivation"""
        app = QApplication.instance()
        if app and QThread.currentThread() != app.thread():
            self._new_connection_signal.emit(conn_data)
        else:
            self._do_handle_new_connection(conn_data)

    @pyqtSlot(dict)
    def _do_handle_new_connection(self, conn_data):
        """Actual implementation - runs on GUI thread"""
        # Check for existing agent
        if any(agent.get('guid') == conn_data['new_client_id'] for agent in self.agent_data):
            print(f"Found existing agent {conn_data['new_client_id']}")
            self.handle_agent_reactivation(conn_data)
            return

        # Check if server provided an alias
        if 'alias' in conn_data:
            self.agent_aliases[conn_data['new_client_id']] = conn_data['alias']

        # Process new agent - keeping original time calculations
        last_seen_str = conn_data.get('last_seen', '')
        last_seen = QDateTime.fromString(last_seen_str, Qt.DateFormat.ISODate) if last_seen_str else QDateTime.currentDateTime()
        seconds = last_seen.secsTo(QDateTime.currentDateTime())
        
        if seconds < 60:
            last_seen_display = f"Last Seen: {seconds} seconds ago"
        elif seconds < 3600:
            minutes = seconds // 60
            last_seen_display = f"Last Seen: {minutes} minutes ago"
        else:
            hours = seconds // 3600
            last_seen_display = f"Last Seen: {hours} hours ago"

        agent_name = f"{conn_data['new_client_id'][:8]}"
        details = [
            f"Hostname: {conn_data['hostname']}",
            f"Internal IP: {conn_data['int_ip']}",
            f"External IP: {conn_data['ext_ip']}",
            f"User: {conn_data['username']}",
            f"Protocol: {conn_data['protocol']}",
            f"Process: {conn_data['process']}",
            f"PID: {conn_data['pid']}",
            f"Architecture: {conn_data['arch']}",
            f"OS: {conn_data['os']}",
            f"Client ID: {conn_data['client_id']}",
            last_seen_display 
        ]

        new_agent = {
            'name': agent_name,
            'details': details,
            'last_seen_timestamp': last_seen,
            'guid': conn_data['new_client_id'],
            'client_id': conn_data['client_id'],
            'os': conn_data.get('os', 'unknown'),
            'hostname': conn_data.get('hostname', 'unknown'),
            'username': conn_data.get('username', 'unknown'),
            'ip': conn_data.get('ext_ip', conn_data.get('int_ip', 'unknown')),
            'deleted': False,  # Initialize with not deleted
            'parent_client_id': conn_data.get('parent_client_id', ''),  # Parent agent for linked agents
            'link_type': conn_data.get('link_type', ''),  # Link type (e.g., "smb")
            'protocol': conn_data.get('protocol', 'HTTPS'),  # Protocol type
        }

        print(f"AgentTreeWidget: Adding agent {agent_name} with details: {details}")
        self.agent_data.append(new_agent)
        # Index by GUID for O(1) lookup
        self.agent_by_guid[new_agent['guid']] = new_agent

        if self.current_view == 'agents':
            print(f"AgentTreeWidget: Current view is agents, adding to tree")
            self.add_agent_to_tree(new_agent)
            print(f"AgentTreeWidget: Added agent {agent_name} to tree view")
        else:
            print(f"AgentTreeWidget: Agent {agent_name} added to data but not to tree (current view is {self.current_view})")


    def create_tree_item(self, data):
        item = QTreeWidgetItem([data['name']])
        for detail in data['details']:
            item.addChild(QTreeWidgetItem([detail]))
        # Store reference to the tree item
        self.agent_items[data['name']] = item
        return item

    def add_agent_to_tree(self, agent):
        """Add a single agent to the tree view.

        Structure: Linked agents are added as SIBLINGS (at the same tree level) as their
        parent, not as children. This way, collapsing a parent only hides its details,
        not the linked agents in the chain. Visual indentation in the display name shows
        the relationship.
        """
        print(f"AgentTreeWidget: add_agent_to_tree called for {agent['name']}")

        # Build display name: prioritize alias, then show more context
        alias = self.agent_aliases.get(agent['guid'])
        guid_len = self.guid_display_length
        guid = agent['guid']

        if alias:
            # If aliased, show "alias (GUID truncated based on settings)"
            if guid_len >= 36:
                display_name = f"{alias} ({guid})"
            else:
                display_name = f"{alias} ({guid[:guid_len]}...)"
        else:
            # No alias: show GUID truncated based on settings
            if guid_len >= 36:
                display_name = guid
            else:
                display_name = f"{guid[:guid_len]}..."

        # Add link indicator for linked agents (visual hierarchy via prefix)
        link_type = agent.get('link_type', '')
        parent_client_id = agent.get('parent_client_id', '')
        if link_type:
            # Calculate depth for visual indentation
            depth = self._get_agent_depth(agent)
            indent = "    " * depth  # 4 spaces per level
            display_name = f"{indent}↳ [{link_type.upper()}] {display_name}"

        # Add tag badges to display name
        agent_tags = self.agent_tags.get(agent['guid'], [])
        if agent_tags:
            tag_badges = " ".join([f"[{tag['name']}]" for tag in agent_tags])
            display_name = f"{display_name} {tag_badges}"

        agent['display_name'] = display_name

        tree_item = QTreeWidgetItem([display_name])
        # Store GUID in item data for filtering and lookups
        tree_item.setData(0, Qt.ItemDataRole.UserRole, agent['guid'])
        # Mark this as an agent item (not a detail item)
        tree_item.setData(0, Qt.ItemDataRole.UserRole + 1, 'agent')

        # Build comprehensive tooltip with all agent info
        tooltip_parts = [
            f"Full GUID: {agent['guid']}",
            f"Hostname: {agent.get('hostname', 'N/A')}",
            f"OS: {agent.get('os', 'N/A')}",
            f"Username: {agent.get('username', 'N/A')}",
            f"IP: {agent.get('ip', 'N/A')}",
        ]
        if alias:
            tooltip_parts.insert(0, f"Alias: {alias}")
        if link_type:
            tooltip_parts.append(f"Link Type: {link_type.upper()}")
            if parent_client_id:
                tooltip_parts.append(f"Parent Agent: {parent_client_id[:16]}...")
        if agent_tags:
            tag_list = ", ".join([f"{tag['name']} ({tag['color']})" for tag in agent_tags])
            tooltip_parts.append(f"Tags: {tag_list}")
        if agent.get('last_seen'):
            tooltip_parts.append(f"Last Seen: {agent['last_seen']}")

        tree_item.setToolTip(0, '\n'.join(tooltip_parts))

        # Add details as direct children (original structure)
        for detail in agent['details']:
            detail_child = QTreeWidgetItem([detail])
            detail_child.setData(0, Qt.ItemDataRole.UserRole + 1, 'detail')
            tree_item.addChild(detail_child)

        # All agents are added as top-level items (siblings)
        # Linked agents show their relationship via visual indentation in the name
        # This means collapsing an agent only hides its details, not linked agents
        self.tree.addTopLevelItem(tree_item)

        self.agent_items[agent['name']] = tree_item

        # Set visibility based on deleted status
        tree_item.setHidden(agent.get('deleted', False))

        if not agent.get('deleted', False):
            # Expand the agent item to show its details
            tree_item.setExpanded(True)

        print(f"AgentTreeWidget: Added agent {agent['name']} to tree (hidden: {agent.get('deleted', False)})")

    def _get_agent_depth(self, agent):
        """Calculate the depth of an agent in the link chain (how many parents up to root)"""
        depth = 0
        current = agent
        visited = set()  # Prevent infinite loops

        while current.get('parent_client_id'):
            parent_id = current['parent_client_id']
            if parent_id in visited:
                break  # Circular reference, stop
            visited.add(parent_id)

            parent = self.agent_by_guid.get(parent_id)
            if not parent:
                break  # Parent not found
            depth += 1
            current = parent

        return depth

    def show_agents(self):
        """Render all agents in the tree regardless of deleted status.

        Agents are displayed as siblings (all top-level) but ordered so that
        linked agents appear immediately after their parent. Visual indentation
        in the display name shows the hierarchy.
        """
        print(f"AgentTreeWidget: show_agents called with {len(self.agent_data)} agents")
        self.tree.clear()
        self.tree.setHeaderLabels(['Agents'])

        # Clear cache since tree is being rebuilt
        self.last_seen_items.clear()
        self.agent_items.clear()

        # Build ordered list: parents followed by their children (depth-first)
        ordered_agents = self._get_hierarchically_ordered_agents()

        # Add all agents in hierarchical order (all as top-level, but ordered correctly)
        for agent in ordered_agents:
            print(f"AgentTreeWidget: Processing agent {agent['name']} for display")
            self.add_agent_to_tree(agent)

        self.current_view = 'agents'
        print("AgentTreeWidget: show_agents complete")

    def _get_hierarchically_ordered_agents(self):
        """Order agents so children appear immediately after their parents (depth-first)."""
        # Build parent -> children map
        agent_guids = {a['guid'] for a in self.agent_data}
        children_map = {}  # parent_guid -> [child_agents]
        root_agents = []

        for agent in self.agent_data:
            parent_id = agent.get('parent_client_id', '')
            if not parent_id or parent_id not in agent_guids:
                root_agents.append(agent)
            else:
                if parent_id not in children_map:
                    children_map[parent_id] = []
                children_map[parent_id].append(agent)

        # Depth-first traversal to build ordered list
        def add_with_children(agent):
            result = [agent]
            for child in children_map.get(agent['guid'], []):
                result.extend(add_with_children(child))
            return result

        ordered = []
        for root in root_agents:
            ordered.extend(add_with_children(root))

        return ordered

    def on_item_clicked(self, item, column):
        if self.current_view == 'agents':
            # Check if this is an agent item (either top-level or linked child)
            # by checking if its GUID is stored in UserRole data
            guid = item.data(0, Qt.ItemDataRole.UserRole)
            if guid:
                # This is an agent item (has GUID)
                agent = self.agent_by_guid.get(guid)
                if agent:
                    self.terminal_widget.add_agent_tab(agent['name'], agent['guid'])
                    return

            # Fallback for top-level items without proper UserRole data
            if not item.parent():
                # Find the agent by tree item reference or display name
                agent = None
                for a in self.agent_data:
                    if a['name'] in self.agent_items and self.agent_items[a['name']] == item:
                        agent = a
                        break

                # If not found by tree item, try by display name
                if not agent:
                    item_text = item.text(0)
                    for a in self.agent_data:
                        if a.get('display_name', a['name']) == item_text:
                            agent = a
                            break

                if agent:
                    self.terminal_widget.add_agent_tab(agent['name'], agent['guid'])

    def show_listeners(self):
        print("AgentTreeWidget: show_listeners called")
        self.tree.clear()
        self.agent_items.clear()
        self.tree.setHeaderLabels(['Active Listeners'])
        
        print(f"AgentTreeWidget: Displaying {len(self.listener_data)} listeners:")
        for listener in self.listener_data:
            print(f"AgentTreeWidget: Creating tree item for listener: {listener['name']}")
            
            # Create root item for listener
            tree_item = QTreeWidgetItem([listener['name']])
            
            # Add details as children
            for detail in listener['details']:
                detail_item = QTreeWidgetItem([detail])
                tree_item.addChild(detail_item)
                print(f"AgentTreeWidget: Added detail '{detail}' to listener {listener['name']}")
            
            self.tree.addTopLevelItem(tree_item)
            self.agent_items[listener['name']] = tree_item
            tree_item.setExpanded(True)
            print(f"AgentTreeWidget: Added listener '{listener['name']}' to tree")

        self.current_view = 'listeners'
        print("AgentTreeWidget: show_listeners complete")

    def get_agent_by_guid(self, guid):
        """Get agent data using the GUID - O(1) lookup with dictionary"""
        return self.agent_by_guid.get(guid, None)

    def add_listener(self, name, protocol, host, port, pipe_name="",
                     get_profile="", post_profile="", server_response_profile="", smb_profile=""):
        print(f"AgentTreeWidget: Adding listener - Name: {name}, Protocol: {protocol}, Host: {host}, Port: {port}, PipeName: {pipe_name}, Profiles: GET={get_profile} POST={post_profile} Response={server_response_profile} SMB={smb_profile}")

        # Check for existing listener to avoid duplicates
        for listener in self.listener_data:
            if listener['name'] == name:
                print(f"AgentTreeWidget: Listener {name} already exists")
                return

        # For SMB listeners, show pipe name and SMB profile instead of HTTP profiles
        if protocol.upper() == "SMB":
            pipe = pipe_name if pipe_name else "spoolss"
            new_listener = {
                'name': name,
                'details': [
                    f'Protocol: {protocol}',
                    f'Pipe: {pipe}',
                    f'SMB Profile: {smb_profile or "default-smb"}'
                ]
            }
        else:
            new_listener = {
                'name': name,
                'details': [
                    f'Protocol: {protocol}',
                    f'Host: {host}',
                    f'Port: {port}',
                    f'GET Profile: {get_profile or "default-get"}',
                    f'POST Profile: {post_profile or "default-post"}',
                    f'Response Profile: {server_response_profile or "default-response"}'
                ]
            }
        self.listener_data.append(new_listener)

        if self.current_view == 'listeners':
            print("AgentTreeWidget: Currently in listeners view, updating tree")
            tree_item = self.create_tree_item(new_listener)
            self.tree.addTopLevelItem(tree_item)
            tree_item.setExpanded(True)

    def remove_listener(self, name):
        """Remove a listener from the data and tree if it exists"""
        self.listener_data = [l for l in self.listener_data if l['name'] != name]
        if self.current_view == 'listeners':
            for i in range(self.tree.topLevelItemCount()):
                if self.tree.topLevelItem(i).text(0) == name:
                    self.tree.takeTopLevelItem(i)
                    print(f"AgentTreeWidget: Listener '{name}' removed from UI.")
                    break

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        menu = QMenu()
        
        if not item:
            # Show view menu for empty space clicks
            view_menu = menu.addMenu("View")
            show_deleted_action = view_menu.addAction("Show Deleted Agents")
            show_deleted_action.setCheckable(True)
            show_deleted_action.setChecked(self.show_deleted)
            show_deleted_action.triggered.connect(self.toggle_deleted_agents)
            menu.exec(self.tree.viewport().mapToGlobal(position))
            return
                
        if self.current_view == 'listeners' and not item.parent():
            delete_action = menu.addAction("Delete Listener")
            action = menu.exec(self.tree.viewport().mapToGlobal(position))
            if action == delete_action:
                self.delete_listener(item.text(0))
                
        elif self.current_view == 'agents' and not item.parent():
            # Get all selected agent items (filter out detail items which have parents)
            selected_items = [i for i in self.tree.selectedItems() if not i.parent()]
            selected_guids = []
            for sel_item in selected_items:
                guid = sel_item.data(0, Qt.ItemDataRole.UserRole)
                if guid:
                    selected_guids.append(guid)

            if len(selected_guids) <= 1:
                # Single agent selected - show full menu
                copy_guid_action = menu.addAction("Copy GUID")
                menu.addSeparator()
                rename_action = menu.addAction("Rename Agent")
                manage_tags_action = menu.addAction("Manage Tags...")
                menu.addSeparator()
                remove_action = menu.addAction("Remove Agent")
                action = menu.exec(self.tree.viewport().mapToGlobal(position))
                if action == copy_guid_action:
                    self.copy_agent_guid(item)
                elif action == rename_action:
                    self.rename_agent(item)
                elif action == manage_tags_action:
                    self.manage_agent_tags(item)
                elif action == remove_action:
                    self.remove_agent(item)
            else:
                # Multiple agents selected - show bulk actions
                count = len(selected_guids)
                remove_all_action = menu.addAction(f"Remove {count} Agents")
                action = menu.exec(self.tree.viewport().mapToGlobal(position))
                if action == remove_all_action:
                    self.remove_agents(selected_guids)

    def copy_agent_guid(self, item):
        """Copy agent GUID to clipboard"""
        from PyQt6.QtWidgets import QApplication

        # Get GUID from item data
        guid = item.data(0, Qt.ItemDataRole.UserRole)
        if guid:
            clipboard = QApplication.clipboard()
            clipboard.setText(guid)
            print(f"Copied GUID to clipboard: {guid}")
        else:
            QMessageBox.warning(self, "Error", "Could not retrieve agent GUID")

    def rename_agent(self, item):
        """Rename an agent (sends to server for persistence)"""
        # Find the agent
        agent = None
        for a in self.agent_data:
            if a['name'] in self.agent_items and self.agent_items[a['name']] == item:
                agent = a
                break
        
        if not agent:
            item_text = item.text(0)
            for a in self.agent_data:
                if a.get('display_name', a['name']) == item_text:
                    agent = a
                    break
        
        if not agent:
            QMessageBox.warning(self, "Error", "Could not find agent data")
            return
        
        # Check connection
        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Error", "Not connected to server")
            return
            
        dialog = QInputDialog(self)
        dialog.setWindowTitle("Rename Agent")
        dialog.setLabelText("Enter new name:")
        dialog.setTextValue(self.agent_aliases.get(agent['guid'], agent['name']))
        
        if dialog.exec():
            new_name = dialog.textValue().strip()
            if new_name:
                # Store locally immediately for responsive UI
                self.agent_aliases[agent['guid']] = new_name
                item.setText(0, new_name)
                agent['display_name'] = new_name
                
                # Send rename request to server
                rename_msg = {
                    "type": "rename_agent",
                    "data": {
                        "agent_id": agent['guid'],
                        "new_name": new_name
                    }
                }
                
                try:
                    asyncio.run_coroutine_threadsafe(
                        self.ws_thread.ws_client.send_message(json.dumps(rename_msg)),
                        self.ws_thread.loop
                    )
                    self.terminal_widget.log_message(f"Agent renamed to '{new_name}'")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to rename agent: {e}")
                    # Revert local change on error
                    del self.agent_aliases[agent['guid']]
                    item.setText(0, agent['name'])
                    del agent['display_name']

    def manage_agent_tags(self, item):
        """Open tag management dialog for an agent"""
        # Find the agent
        agent = None
        for a in self.agent_data:
            if a['name'] in self.agent_items and self.agent_items[a['name']] == item:
                agent = a
                break

        if not agent:
            item_text = item.text(0)
            for a in self.agent_data:
                if a.get('display_name', a['name']) == item_text:
                    agent = a
                    break

        if not agent:
            QMessageBox.warning(self, "Error", "Could not find agent data")
            return

        # Check connection
        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Error", "Not connected to server")
            return

        # Get current tags for this agent
        agent_guid = agent['guid']
        current_tags = self.agent_tags.get(agent_guid, [])

        # Get display name
        display_name = self.agent_aliases.get(agent_guid, agent['name'])

        # Import and show tag manager dialog
        from gui.widgets.tag_manager_dialog import TagManagerDialog
        dialog = TagManagerDialog(agent_guid, display_name, current_tags, self.ws_thread, self)

        if dialog.exec():
            # Dialog was accepted - tags were saved
            self.terminal_widget.log_message(f"Tags updated for agent {display_name}")

    def delete_listener(self, name):
        """Delete a listener after verifying connection state."""
        #print("\nDEBUG: Starting delete_listener")
        #print(f"DEBUG: ws_thread exists: {self.ws_thread is not None}")
        
        # Detailed connection verification
        if not self.ws_thread:
            #print("DEBUG: No WebSocket thread available")
            QMessageBox.warning(self, "Warning", "Not connected to server")
            return
            
        if not hasattr(self.ws_thread, 'ws_client'):
            #print("DEBUG: No WebSocket client in thread")
            QMessageBox.warning(self, "Warning", "Not connected to server")
            return
            
        if not self.ws_thread.ws_client:
            #print("DEBUG: WebSocket client is None")
            QMessageBox.warning(self, "Warning", "Not connected to server")
            return
            
        if not self.ws_thread.ws_client.websocket:
            #print("DEBUG: No active WebSocket connection")
            QMessageBox.warning(self, "Warning", "Not connected to server")
            return
            
        if not self.ws_thread.ws_client.connected:
            #print("DEBUG: WebSocket is not in connected state")
            QMessageBox.warning(self, "Warning", "Not connected to server")
            return

        # Connection verified, proceed with deletion
        reply = QMessageBox.question(self, 'Delete Listener',
                                f'Are you sure you want to delete listener "{name}"?',
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            delete_msg = {
                "type": "delete_listener",
                "data": {
                    "name": name
                }
            }
            #print("DEBUG: Preparing to send delete message")
            
            try:
                if not self.ws_thread.loop:
                    #print("DEBUG: No event loop available")
                    QMessageBox.warning(self, "Error", "Connection error: No event loop")
                    return
                    
                #print("DEBUG: Sending delete message via WebSocket")
                future = asyncio.run_coroutine_threadsafe(
                    self.ws_thread.ws_client.send_message(json.dumps(delete_msg)),
                    self.ws_thread.loop
                )
                
                # Wait for the result with a timeout
                future.result(timeout=5)
                print(f"AgentTreeWidget: Delete message sent for listener '{name}'")
                # Don't remove the listener here - wait for server confirmation
                
            except asyncio.TimeoutError:
                print("ERROR: Delete message timed out")
                QMessageBox.warning(self, "Error", "Failed to delete listener: Operation timed out")
            except Exception as e:
                print(f"ERROR: Failed to send delete message: {e}")
                QMessageBox.warning(self, "Error", f"Failed to delete listener: {str(e)}")

    def get_listener_names(self):
        return [listener['name'] for listener in self.listener_data]

    def loadStateFromDatabase(self):
        print("\nAgentTreeWidget: loadStateFromDatabase called")

        # Clear current state
        print("\nAgentTreeWidget: Clearing current data...")
        self.agent_data.clear()
        self.listener_data.clear()
        self.agent_by_guid.clear()  # Clear GUID index
        self.agent_tags.clear()  # Clear tags
        self.tree.clear()
        
        try:
            with sqlite3.connect("state.db") as conn:
                print("\nDEBUG: Database connection established")
                
                # Verify connections table contents
                cursor = conn.execute("SELECT COUNT(*) FROM connections")
                count = cursor.fetchone()[0]
                print(f"DEBUG: Found {count} total connections in database")
                
                # Print sample of raw connections data
                cursor = conn.execute("SELECT * FROM connections LIMIT 5")
                print("\nDEBUG: Sample of raw connections data:")
                columns = [description[0] for description in cursor.description]
                print(f"Columns: {columns}")
                rows = cursor.fetchall()
                for row in rows:
                    print(f"  {row}")
                
                # Load listeners first
                print("\nAgentTreeWidget: Loading listeners from database")
                cursor = conn.execute("""
                    SELECT id, name, protocol, port, ip, pipe_name,
                           get_profile, post_profile, server_response_profile, smb_profile
                    FROM listeners
                    ORDER BY name ASC
                """)
                listeners = cursor.fetchall()
                print(f"AgentTreeWidget: Found {len(listeners)} listeners in database")

                for row in listeners:
                    print(f"AgentTreeWidget: Processing listener {row[1]}")
                    protocol = row[2]
                    # Get profile values with defaults
                    get_profile = row[6] if len(row) > 6 and row[6] else "default-get"
                    post_profile = row[7] if len(row) > 7 and row[7] else "default-post"
                    response_profile = row[8] if len(row) > 8 and row[8] else "default-response"
                    smb_profile = row[9] if len(row) > 9 and row[9] else "default-smb"

                    # For SMB listeners, show pipe name and SMB profile instead of HTTP profiles
                    if protocol == "SMB":
                        pipe_name = row[5] if len(row) > 5 and row[5] else "spoolss"
                        listener = {
                            'name': row[1],
                            'details': [
                                f'Protocol: {protocol}',
                                f'Pipe: {pipe_name}',
                                f'SMB Profile: {smb_profile}'
                            ]
                        }
                    else:
                        listener = {
                            'name': row[1],
                            'details': [
                                f'Protocol: {protocol}',
                                f'Host: {row[4]}',
                                f'Port: {row[3]}',
                                f'GET Profile: {get_profile}',
                                f'POST Profile: {post_profile}',
                                f'Response Profile: {response_profile}'
                            ]
                        }
                    self.listener_data.append(listener)
                    print(f"AgentTreeWidget: Added listener '{listener['name']}' to data")

                # Load all agents
                print("\nAgentTreeWidget: Loading all agents from database")
                cursor = conn.execute("""
                    SELECT DISTINCT
                        newclient_id,
                        hostname,
                        intIP,
                        extIP,
                        username,
                        protocol,
                        process,
                        pid,
                        arch,
                        os,
                        client_id,
                        lastSEEN,
                        deleted_at,
                        alias,
                        parent_client_id,
                        link_type,
                        COUNT(*) OVER () as total_count
                    FROM connections
                    ORDER BY lastSEEN DESC
                """)
                
                fields = [description[0] for description in cursor.description]
                print(f"\nDEBUG: Query fields: {fields}")
                
                rows = cursor.fetchall()
                if not rows:
                    print("DEBUG: No agents found in database")
                else:
                    total_agents = rows[0][-1]  # Get total from window function
                    print(f"\nDEBUG: Processing {total_agents} agents")
                    
                    for row in rows:
                        print(f"\nDEBUG: Processing row: {row}")
                        agent_name = f"{row[0][:8]}"  # First 8 chars of newclient_id
                        
                        # Handle timestamp conversion
                        try:
                            last_seen = QDateTime.fromString(row[11], Qt.DateFormat.ISODate)
                            if not last_seen.isValid():
                                print(f"DEBUG: Invalid timestamp format: {row[11]}")
                                last_seen = QDateTime.currentDateTime()
                        except Exception as e:
                            print(f"DEBUG: Timestamp conversion error: {e}")
                            last_seen = QDateTime.currentDateTime()

                        # Check deleted status - handle both string timestamps and JSON dictionary format
                        deleted_at = row[12]
                        is_deleted = False

                        if deleted_at:
                            try:
                                # Check if it's a JSON dictionary format
                                if isinstance(deleted_at, dict):
                                    is_deleted = deleted_at.get('Valid', False)
                                # Check if it's a timestamp that's not the zero value
                                elif isinstance(deleted_at, str):
                                    is_deleted = deleted_at != '0001-01-01T00:00:00Z' and deleted_at != 'NULL'
                            except:
                                is_deleted = False

                        print(f"DEBUG: deleted_at value: {deleted_at}, type: {type(deleted_at)}, is_deleted: {is_deleted}")
                        
                        details = [
                            f"Hostname: {row[1]}",      # hostname
                            f"Internal IP: {row[2]}",   # intIP
                            f"External IP: {row[3]}",   # extIP
                            f"User: {row[4]}",         # username
                            f"Protocol: {row[5]}",     # protocol
                            f"Process: {row[6]}",      # process
                            f"PID: {row[7]}",          # pid
                            f"Architecture: {row[8]}",  # arch
                            f"OS: {row[9]}",          # os
                            f"Client ID: {row[10]}",   # client_id
                            "Last Seen: Processing..."  # Will be updated by timer
                        ]

                        agent = {
                            'name': agent_name,
                            'details': details,
                            'last_seen_timestamp': last_seen,
                            'guid': row[0],
                            'client_id': row[10],
                            'os': row[9],
                            'hostname': row[1],
                            'username': row[4],
                            'ip': row[3] if row[3] else row[2],  # Prefer external IP, fallback to internal
                            'deleted': is_deleted,
                            'parent_client_id': row[14] if row[14] else '',  # For linked agents
                            'link_type': row[15] if row[15] else '',         # Link type (e.g., "smb")
                            'protocol': row[5],  # Protocol type
                        }

                        # Add this to read the alias from column 13
                        if row[13]:  # alias column
                            self.agent_aliases[row[0]] = row[13]
                            agent['display_name'] = row[13]
                            
                        print(f"DEBUG: Created agent data structure: {agent}")
                        self.agent_data.append(agent)
                        # Index by GUID for O(1) lookup
                        self.agent_by_guid[agent['guid']] = agent
                        print(f"AgentTreeWidget: Added agent {agent_name} (deleted: {is_deleted})")
                        
                    print(f"\nDEBUG: Successfully loaded {len(self.agent_data)} agents")

                # Load agent tags
                print("\nAgentTreeWidget: Loading agent tags from database")
                cursor = conn.execute("""
                    SELECT agent_guid, tag_name, tag_color
                    FROM agent_tags
                    ORDER BY agent_guid, tag_name ASC
                """)
                tags_rows = cursor.fetchall()
                for row in tags_rows:
                    agent_guid = row[0]
                    tag = {"name": row[1], "color": row[2]}
                    if agent_guid not in self.agent_tags:
                        self.agent_tags[agent_guid] = []
                    self.agent_tags[agent_guid].append(tag)
                print(f"AgentTreeWidget: Loaded tags for {len(self.agent_tags)} agents")

        except sqlite3.Error as e:
            print(f"\nDatabase error: {e}")
            traceback.print_exc()
        except Exception as e:
            print(f"\nUnexpected error: {e}")
            traceback.print_exc()

        # Display the current view
        print(f"\nAgentTreeWidget: Current view is {self.current_view}")
        if self.current_view == 'listeners':
            print("AgentTreeWidget: Showing listeners view")
            self.show_listeners()
        else:
            print(f"AgentTreeWidget: Showing agents view (total agents: {len(self.agent_data)})")
            self.show_agents()

        print("\nAgentTreeWidget: loadStateFromDatabase completed")

    def update_existing_connection(self, connection_data):
        """Thread-safe method to update an existing agent in the tree."""
        app = QApplication.instance()
        if app and QThread.currentThread() != app.thread():
            self._update_connection_signal.emit(connection_data)
        else:
            self._do_update_existing_connection(connection_data)

    @pyqtSlot(dict)
    def _do_update_existing_connection(self, connection_data):
        """Actual implementation - runs on GUI thread"""
        agent_name = f"{connection_data['newclient_id'][:8]}"

        # Find and update the agent
        for agent in self.agent_data:
            if agent['guid'] == connection_data['newclient_id']:
                # Update the agent's details
                agent['details'] = [
                    f"Hostname: {connection_data['hostname']}",
                    f"Internal IP: {connection_data['int_ip']}",
                    f"External IP: {connection_data['ext_ip']}",
                    f"User: {connection_data['username']}",
                    f"Protocol: {connection_data['protocol']}",
                    f"Process: {connection_data['process']}",
                    f"PID: {connection_data['pid']}",
                    f"Architecture: {connection_data['arch']}",
                    f"OS: {connection_data['os']}",
                    f"Client ID: {connection_data['client_id']}",
                    "Last Seen: 0 seconds ago"
                ]
                agent['last_seen_timestamp'] = QDateTime.currentDateTime()

                # Update the tree view
                tree_item = self.agent_items.get(agent_name)
                if tree_item:
                    tree_item.takeChildren()
                    for detail in agent['details']:
                        tree_item.addChild(QTreeWidgetItem([detail]))
                break

    def remove_agent(self, item):
        """Mark an agent as deleted and hide it from view"""
        # Find the agent by iterating through agent_data
        # since item.text(0) might be the renamed alias, not the original name
        agent = None
        for a in self.agent_data:
            # Check if this agent's tree item matches
            if a['name'] in self.agent_items and self.agent_items[a['name']] == item:
                agent = a
                break
        
        # If still not found, try by display name (in case of alias)
        if not agent:
            item_text = item.text(0)
            for a in self.agent_data:
                if a.get('display_name', a['name']) == item_text:
                    agent = a
                    break
        
        if not agent:
            QMessageBox.warning(self, "Error", "Could not find agent data")
            return

        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Error", "Not connected to server")
            return

        # Show confirmation dialog
        agent_display_name = agent.get('display_name', agent['name'])
        reply = QMessageBox.question(
            self, 
            'Remove Agent',
            f'Are you sure you want to remove agent "{agent_display_name}"?\n\n'
            f'Agent ID: {agent["guid"][:12]}...',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return

        msg = {
            "type": "remove_agent",
            "data": {
                "agent_id": agent['guid'],  # Always use the GUID for server communication
                "username": self.ws_thread.username
            }
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self.ws_thread.ws_client.send_message(json.dumps(msg)),
                self.ws_thread.loop
            )
            # Mark agent as deleted instead of removing completely
            agent['deleted'] = True
            item.setHidden(True)  # Hide from view but maintain data
            self.terminal_widget.log_message(f"Agent '{agent_display_name}' (ID: {agent['guid'][:12]}...) removed")
            # Emit signal to sync other views
            self.agents_removed.emit([agent['guid']])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove agent: {e}")

    def remove_agents(self, guids):
        """Remove multiple agents by their GUIDs"""
        if not guids:
            return

        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Error", "Not connected to server")
            return

        count = len(guids)
        reply = QMessageBox.question(
            self,
            'Remove Agents',
            f'Are you sure you want to remove {count} agent(s)?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        removed_guids = []
        for guid in guids:
            agent = self.agent_by_guid.get(guid)
            if not agent:
                continue

            msg = {
                "type": "remove_agent",
                "data": {
                    "agent_id": guid,
                    "username": self.ws_thread.username
                }
            }

            try:
                asyncio.run_coroutine_threadsafe(
                    self.ws_thread.ws_client.send_message(json.dumps(msg)),
                    self.ws_thread.loop
                )
                # Mark agent as deleted
                agent['deleted'] = True
                # Hide the tree item
                if agent['name'] in self.agent_items:
                    self.agent_items[agent['name']].setHidden(True)
                removed_guids.append(guid)
            except Exception as e:
                print(f"Failed to remove agent {guid[:12]}: {e}")

        if removed_guids:
            self.terminal_widget.log_message(f"Removed {len(removed_guids)} agent(s)")
            # Emit signal to sync other views
            self.agents_removed.emit(removed_guids)

    def handle_agent_reactivation(self, conn_data):
        """Handle reactivation of an existing agent"""
        agent = next((a for a in self.agent_data if a['guid'] == conn_data['new_client_id']), None)
        if agent:
            # Calculate last seen time same as new connections
            last_seen_str = conn_data.get('last_seen', '')
            last_seen = QDateTime.fromString(last_seen_str, Qt.DateFormat.ISODate) if last_seen_str else QDateTime.currentDateTime()
            seconds = last_seen.secsTo(QDateTime.currentDateTime())
            
            if seconds < 60:
                last_seen_display = f"Last Seen: {seconds} seconds ago"
            elif seconds < 3600:
                minutes = seconds // 60
                last_seen_display = f"Last Seen: {minutes} minutes ago"
            else:
                hours = seconds // 3600
                last_seen_display = f"Last Seen: {hours} hours ago"

            # Clear deleted flag and update timestamp
            agent['deleted'] = False 
            agent['last_seen_timestamp'] = last_seen

            # Update agent details with current information
            agent['details'] = [
                f"Hostname: {conn_data['hostname']}",
                f"Internal IP: {conn_data['int_ip']}",
                f"External IP: {conn_data['ext_ip']}",
                f"User: {conn_data['username']}",
                f"Protocol: {conn_data['protocol']}",
                f"Process: {conn_data['process']}",
                f"PID: {conn_data['pid']}",
                f"Architecture: {conn_data['arch']}",
                f"OS: {conn_data['os']}",
                f"Client ID: {conn_data['client_id']}",
                last_seen_display
            ]

            # Update tree view if we're in agents view
            if self.current_view == 'agents':
                if agent['name'] in self.agent_items:
                    item = self.agent_items[agent['name']]
                    item.setHidden(False)  # Make sure item is visible
                    item.takeChildren()  # Clear old details
                    for detail in agent['details']:
                        item.addChild(QTreeWidgetItem([detail]))
                    item.setExpanded(True)
                else:
                    # If somehow the item isn't in the tree, add it
                    self.add_agent_to_tree(agent)

            self.terminal_widget.log_message(f"Agent {agent['name']} reactivated")

    def update_agent_in_tree(self, agent):
        """Update or add an agent in the tree view"""
        if self.current_view == 'agents':
            if agent['name'] not in self.agent_items:
                self.add_agent_to_tree(agent)
            else:
                item = self.agent_items[agent['name']]
                item.setHidden(False)  # Make sure item is visible
                item.takeChildren()  # Remove old details
                for detail in agent['details']:
                    item.addChild(QTreeWidgetItem([detail]))
                item.setExpanded(True)  # Expand to show details

    def add_show_deleted_action(self):
        self.show_deleted = False  # Track state
        view_menu = QMenu("View", self)
        self.show_deleted_action = view_menu.addAction("Show Deleted Agents")
        self.show_deleted_action.setCheckable(True)
        self.show_deleted_action.triggered.connect(self.toggle_deleted_agents)
        return view_menu

    def toggle_deleted_agents(self, checked):
        self.show_deleted = checked
        self.refresh_agent_view()

    def refresh_agent_view(self):
        self.tree.clear()
        for agent in self.agent_data:
            if not self.show_deleted and agent.get('deleted'):
                continue
            self.add_agent_to_tree(agent)

    def handle_agent_deleted(self, data):
        agent_guid = data.get('agent_id')
        agent = next((a for a in self.agent_data if a['guid'] == agent_guid), None)
        if agent:
            agent['deleted'] = True
            if self.current_view == 'agents':
                if agent['name'] in self.agent_items:
                    item = self.agent_items[agent['name']]
                    item.setHidden(True)
            self.terminal_widget.log_message(f"Agent {agent['name']} removed")

    def handle_agent_checkin(self, agent_id, timestamp):
        agent = next((a for a in self.agent_data if a['guid'] == agent_id), None)
        if agent and agent.get('deleted'):
            agent['deleted'] = False
            if self.current_view == 'agents':
                if agent['name'] not in self.agent_items:
                    self.add_agent_to_tree(agent)
                else:
                    self.agent_items[agent['name']].setHidden(False)
            self.terminal_widget.log_message(f"Agent {agent['name']} reconnected")

    def handle_agent_renamed(self, data):
        """Thread-safe handler for agent rename notification from server"""
        app = QApplication.instance()
        if app and QThread.currentThread() != app.thread():
            self._agent_renamed_signal.emit(data)
        else:
            self._do_handle_agent_renamed(data)

    @pyqtSlot(dict)
    def _do_handle_agent_renamed(self, data):
        """Actual implementation - runs on GUI thread"""
        agent_id = data.get('agent_id')
        new_name = data.get('new_name')

        # Update local alias cache
        self.agent_aliases[agent_id] = new_name

        # Find and update the agent
        for agent in self.agent_data:
            if agent['guid'] == agent_id:
                # Build display name with GUID (same format as add_agent_to_tree)
                display_name = f"{new_name} ({agent_id[:16]}...)"
                agent['display_name'] = display_name

                # Update tree view if visible
                if self.current_view == 'agents' and agent['name'] in self.agent_items:
                    item = self.agent_items[agent['name']]
                    item.setText(0, display_name)

                    # Update tooltip as well
                    tooltip_parts = [
                        f"Alias: {new_name}",
                        f"Full GUID: {agent_id}",
                        f"Hostname: {agent.get('hostname', 'N/A')}",
                        f"OS: {agent.get('os', 'N/A')}",
                        f"Username: {agent.get('username', 'N/A')}",
                        f"IP: {agent.get('ip', 'N/A')}",
                    ]
                    if agent.get('last_seen'):
                        tooltip_parts.append(f"Last Seen: {agent['last_seen']}")
                    item.setToolTip(0, '\n'.join(tooltip_parts))

                self.terminal_widget.log_message(f"Agent {agent_id[:8]} renamed to '{new_name}'")
                break

    def handle_agent_tags_updated(self, data):
        """Thread-safe handler for agent tag update notification from server"""
        app = QApplication.instance()
        if app and QThread.currentThread() != app.thread():
            self._agent_tags_updated_signal.emit(data)
        else:
            self._do_handle_agent_tags_updated(data)

    @pyqtSlot(dict)
    def _do_handle_agent_tags_updated(self, data):
        """Actual implementation - runs on GUI thread"""
        agent_id = data.get('agent_id')
        tags = data.get('tags', [])

        print(f"AgentTreeWidget: Tags updated for {agent_id[:8]}: {tags}")

        # Update local tags cache
        if tags:
            self.agent_tags[agent_id] = tags
        elif agent_id in self.agent_tags:
            # No tags remaining, remove from dict
            del self.agent_tags[agent_id]

        # Update database
        if hasattr(self, 'terminal_widget') and hasattr(self.terminal_widget, 'ws_thread'):
            from utils.database import StateDatabase
            db = StateDatabase()
            db.update_agent_tags(agent_id, tags)

        # Update tree display if agent is visible
        for agent in self.agent_data:
            if agent['guid'] == agent_id:
                if self.current_view == 'agents' and agent['name'] in self.agent_items:
                    item = self.agent_items[agent['name']]

                    # Rebuild display name with tags
                    alias = self.agent_aliases.get(agent_id)
                    if alias:
                        display_name = f"{alias} ({agent_id[:16]}...)"
                    else:
                        display_name = f"{agent_id[:16]}..."

                    # Add tag badges
                    if tags:
                        tag_badges = " ".join([f"[{tag['name']}]" for tag in tags])
                        display_name = f"{display_name} {tag_badges}"

                    # Update tree item
                    item.setText(0, display_name)
                    agent['display_name'] = display_name

                    # Update tooltip
                    tooltip_parts = [
                        f"Full GUID: {agent_id}",
                        f"Hostname: {agent.get('hostname', 'N/A')}",
                        f"OS: {agent.get('os', 'N/A')}",
                        f"Username: {agent.get('username', 'N/A')}",
                        f"IP: {agent.get('ip', 'N/A')}",
                    ]
                    if alias:
                        tooltip_parts.insert(0, f"Alias: {alias}")
                    if tags:
                        tag_list = ", ".join([f"{tag['name']} ({tag['color']})" for tag in tags])
                        tooltip_parts.append(f"Tags: {tag_list}")
                    if agent.get('last_seen'):
                        tooltip_parts.append(f"Last Seen: {agent['last_seen']}")
                    item.setToolTip(0, '\n'.join(tooltip_parts))

                    # Log message
                    tag_names = [tag['name'] for tag in tags]
                    self.terminal_widget.log_message(
                        f"Agent {agent_id[:8]} tags updated: {', '.join(tag_names) if tag_names else '(none)'}"
                    )
                break

    def handle_link_update(self, data):
        """Handle link update notification from server (link or unlink event).

        Since agents are displayed as siblings with visual indentation, we simply
        update the display name and rebuild the tree to ensure proper ordering.
        """
        agent_id = data.get('agent_id')
        parent_client_id = data.get('parent_client_id', '')
        link_type = data.get('link_type', '')

        print(f"AgentTreeWidget: Link update for {agent_id[:8]}: parent={parent_client_id[:8] if parent_client_id else 'None'}, type={link_type}")

        # Find and update the agent
        agent = self.agent_by_guid.get(agent_id)
        if not agent:
            print(f"AgentTreeWidget: Agent {agent_id[:8]} not found for link update")
            return

        # Check if anything actually changed
        old_parent = agent.get('parent_client_id', '')
        old_link_type = agent.get('link_type', '')
        if old_parent == parent_client_id and old_link_type == link_type:
            print(f"AgentTreeWidget: No change in link status for {agent_id[:8]}")
            return

        # Update agent data
        agent['parent_client_id'] = parent_client_id
        agent['link_type'] = link_type

        # Rebuild the tree to get proper ordering and visual indentation
        # This is simpler than trying to reorder individual items
        if self.current_view == 'agents':
            self.show_agents()

        # Log message
        if parent_client_id:
            self.terminal_widget.log_message(
                f"Agent {agent_id[:8]} linked to {parent_client_id[:8]} via {link_type.upper()}"
            )
        else:
            self.terminal_widget.log_message(
                f"Agent {agent_id[:8]} unlinked (moved to top-level)"
            )