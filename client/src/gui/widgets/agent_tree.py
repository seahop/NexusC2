#agent_tree.py
from PyQt6.QtWidgets import (QTreeWidget, QTreeWidgetItem, QWidget, QVBoxLayout,
                              QMessageBox, QMenu, QInputDialog, QLineEdit, QHBoxLayout, QLabel)
from PyQt6.QtCore import QTimer, QDateTime, Qt, pyqtSlot
import json
import asyncio
import sqlite3
import traceback
from utils.constants import AGENT_TREE_UPDATE_INTERVAL

class AgentTreeWidget(QWidget):
    def __init__(self, terminal_widget):
        super().__init__()
        self.terminal_widget = terminal_widget
        layout = QVBoxLayout()
        self.is_state_loaded = False

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

    @pyqtSlot(dict)
    def handle_new_connection(self, conn_data):
        """Handle new connection or reactivation"""
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
            'deleted': False  # Initialize with not deleted
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
        """Add a single agent to the tree view."""
        print(f"AgentTreeWidget: add_agent_to_tree called for {agent['name']}")

        # Build display name: prioritize alias, then show more context
        alias = self.agent_aliases.get(agent['guid'])
        if alias:
            # If aliased, show "alias (first 16 chars of GUID)"
            display_name = f"{alias} ({agent['guid'][:16]}...)"
        else:
            # No alias: show first 16 characters instead of 8 for better distinction
            display_name = f"{agent['guid'][:16]}..."

        agent['display_name'] = display_name

        tree_item = QTreeWidgetItem([display_name])
        # Store GUID in item data for filtering and lookups
        tree_item.setData(0, Qt.ItemDataRole.UserRole, agent['guid'])

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
        if agent.get('last_seen'):
            tooltip_parts.append(f"Last Seen: {agent['last_seen']}")

        tree_item.setToolTip(0, '\n'.join(tooltip_parts))

        for detail in agent['details']:
            tree_item.addChild(QTreeWidgetItem([detail]))

        self.tree.addTopLevelItem(tree_item)
        self.agent_items[agent['name']] = tree_item
        
        # Set visibility based on deleted status
        tree_item.setHidden(agent.get('deleted', False))
        
        if not agent.get('deleted', False):
            tree_item.setExpanded(True)
        
        print(f"AgentTreeWidget: Added agent {agent['name']} to tree (hidden: {agent.get('deleted', False)})")

    def show_agents(self):
        """Render all agents in the tree regardless of deleted status."""
        print(f"AgentTreeWidget: show_agents called with {len(self.agent_data)} agents")
        self.tree.clear()
        self.tree.setHeaderLabels(['Agents'])

        # Clear cache since tree is being rebuilt
        self.last_seen_items.clear()

        for agent in self.agent_data:
            print(f"AgentTreeWidget: Processing agent {agent['name']} for display")
            print(f"AgentTreeWidget: Agent details: {agent}")
            self.add_agent_to_tree(agent)

        self.current_view = 'agents'
        print("AgentTreeWidget: show_agents complete")

    def on_item_clicked(self, item, column):
        if self.current_view == 'agents' and not item.parent():
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

    def add_listener(self, name, protocol, host, port):
        print(f"AgentTreeWidget: Adding listener - Name: {name}, Protocol: {protocol}, Host: {host}, Port: {port}")

        # Check for existing listener to avoid duplicates
        for listener in self.listener_data:
            if listener['name'] == name:
                print(f"AgentTreeWidget: Listener {name} already exists")
                return

        new_listener = {
            'name': name,
            'details': [
                f'Protocol: {protocol}',
                f'Host: {host}',
                f'Port: {port}'
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
            copy_guid_action = menu.addAction("Copy GUID")
            menu.addSeparator()
            rename_action = menu.addAction("Rename Agent")
            remove_action = menu.addAction("Remove Agent")
            action = menu.exec(self.tree.viewport().mapToGlobal(position))
            if action == copy_guid_action:
                self.copy_agent_guid(item)
            elif action == rename_action:
                self.rename_agent(item)
            elif action == remove_action:
                self.remove_agent(item)

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
                    SELECT id, name, protocol, port, ip 
                    FROM listeners
                    ORDER BY name ASC
                """)
                listeners = cursor.fetchall()
                print(f"AgentTreeWidget: Found {len(listeners)} listeners in database")
                
                for row in listeners:
                    print(f"AgentTreeWidget: Processing listener {row[1]}")
                    listener = {
                        'name': row[1],
                        'details': [
                            f'Protocol: {row[2]}',
                            f'Host: {row[4]}',
                            f'Port: {row[3]}'
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
                            'deleted': is_deleted
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
        """Update an existing agent in the tree."""
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
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to remove agent: {e}")

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
        """Handle agent rename notification from server"""
        agent_id = data.get('agent_id')
        new_name = data.get('new_name')
        
        # Update local alias cache
        self.agent_aliases[agent_id] = new_name
        
        # Find and update the agent
        for agent in self.agent_data:
            if agent['guid'] == agent_id:
                agent['display_name'] = new_name
                
                # Update tree view if visible
                if self.current_view == 'agents' and agent['name'] in self.agent_items:
                    item = self.agent_items[agent['name']]
                    item.setText(0, new_name)
                
                self.terminal_widget.log_message(f"Agent {agent_id[:8]} renamed to '{new_name}'")
                break