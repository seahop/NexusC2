# widgets/listeners.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget,
                           QTableWidgetItem, QHeaderView, QMenu, QMessageBox)
from PyQt6.QtCore import Qt
import asyncio
import json


class ListenersWidget(QWidget):
    """Widget for displaying listeners in a tab view."""

    def __init__(self, agent_tree=None, ws_thread=None):
        super().__init__()
        self.agent_tree = agent_tree
        self.ws_thread = ws_thread
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Create table widget with profile columns
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            'Name', 'Protocol', 'Host/Pipe', 'Port',
            'GET/SMB Profile', 'POST Profile', 'Response Profile'
        ])

        # Set table properties
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)

        # Enable context menu
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.table)
        self.setLayout(layout)

    def refresh_listeners(self):
        """Refresh the listeners table from agent_tree data."""
        if not self.agent_tree:
            return

        self.table.setRowCount(0)

        for listener in self.agent_tree.listener_data:
            self.add_listener_row(listener)

        self.table.resizeColumnsToContents()

    def add_listener_row(self, listener):
        """Add a listener row to the table."""
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        name = listener.get('name', '')

        # Parse details array to extract fields
        protocol = ''
        host = ''
        port = ''
        pipe_name = ''
        get_profile = ''
        post_profile = ''
        response_profile = ''
        smb_profile = ''

        for detail in listener.get('details', []):
            if detail.startswith('Protocol:'):
                protocol = detail.split(':', 1)[1].strip().upper()
            elif detail.startswith('Host:'):
                host = detail.split(':', 1)[1].strip()
            elif detail.startswith('Port:'):
                port = detail.split(':', 1)[1].strip()
            elif detail.startswith('Pipe:'):
                pipe_name = detail.split(':', 1)[1].strip()
            elif detail.startswith('GET Profile:'):
                get_profile = detail.split(':', 1)[1].strip()
            elif detail.startswith('POST Profile:'):
                post_profile = detail.split(':', 1)[1].strip()
            elif detail.startswith('Response Profile:'):
                response_profile = detail.split(':', 1)[1].strip()
            elif detail.startswith('SMB Profile:'):
                smb_profile = detail.split(':', 1)[1].strip()

        # For SMB listeners, show pipe name in Host/Pipe column
        host_or_pipe = pipe_name if protocol == 'SMB' else host

        # Set Name
        name_item = QTableWidgetItem(name)
        name_item.setData(Qt.ItemDataRole.UserRole, name)  # Store name for context menu
        self.table.setItem(row_position, 0, name_item)

        # Set Protocol with color coding
        protocol_item = QTableWidgetItem(protocol)
        if protocol == 'HTTPS':
            protocol_item.setForeground(Qt.GlobalColor.green)
        elif protocol == 'HTTP':
            protocol_item.setForeground(Qt.GlobalColor.yellow)
        elif protocol == 'SMB':
            protocol_item.setForeground(Qt.GlobalColor.cyan)
        self.table.setItem(row_position, 1, protocol_item)

        # Set Host/Pipe
        host_item = QTableWidgetItem(host_or_pipe)
        self.table.setItem(row_position, 2, host_item)

        # Set Port (empty for SMB)
        port_item = QTableWidgetItem(port if protocol != 'SMB' else '-')
        self.table.setItem(row_position, 3, port_item)

        # Set Profile columns - for SMB, show SMB profile in GET column and '-' for others
        if protocol == 'SMB':
            get_profile_item = QTableWidgetItem(smb_profile or 'default-smb')
            post_profile_item = QTableWidgetItem('-')
            response_profile_item = QTableWidgetItem('-')
        else:
            get_profile_item = QTableWidgetItem(get_profile or 'default-get')
            post_profile_item = QTableWidgetItem(post_profile or 'default-post')
            response_profile_item = QTableWidgetItem(response_profile or 'default-response')

        self.table.setItem(row_position, 4, get_profile_item)
        self.table.setItem(row_position, 5, post_profile_item)
        self.table.setItem(row_position, 6, response_profile_item)

    def show_context_menu(self, position):
        """Show context menu for listener actions."""
        row = self.table.rowAt(position.y())
        if row < 0:
            return

        item = self.table.item(row, 0)
        if not item:
            return

        listener_name = item.data(Qt.ItemDataRole.UserRole)

        menu = QMenu()
        delete_action = menu.addAction("Delete Listener")

        global_pos = self.table.viewport().mapToGlobal(position)
        action = menu.exec(global_pos)

        if action == delete_action:
            self.delete_listener(listener_name)

    def delete_listener(self, listener_name):
        """Delete a listener via websocket."""
        reply = QMessageBox.question(
            self,
            'Delete Listener',
            f'Are you sure you want to delete listener "{listener_name}"?',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Error", "Not connected to server")
            return

        # Send delete request
        message = {
            "type": "delete_listener",
            "data": {
                "name": listener_name
            }
        }

        try:
            asyncio.run_coroutine_threadsafe(
                self.ws_thread.ws_client.send_message(json.dumps(message)),
                self.ws_thread.loop
            )
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete listener: {e}")

    def set_agent_tree(self, agent_tree):
        """Set the agent tree reference."""
        self.agent_tree = agent_tree

    def set_ws_thread(self, ws_thread):
        """Set the websocket thread reference."""
        self.ws_thread = ws_thread

    def add_listener(self, listener_data):
        """Add a new listener to the table from broadcast data."""
        # Convert broadcast data format to internal format
        protocol = listener_data.get('protocol', '').upper()
        is_smb = protocol == 'SMB'

        if is_smb:
            # SMB listeners use pipe name and SMB profile
            listener = {
                'name': listener_data.get('name', ''),
                'details': [
                    f"Protocol: {protocol}",
                    f"Pipe: {listener_data.get('pipe_name', 'spoolss')}",
                    f"SMB Profile: {listener_data.get('smb_profile', 'default-smb')}"
                ]
            }
        else:
            # HTTP/HTTPS listeners use host, port, and HTTP profiles
            listener = {
                'name': listener_data.get('name', ''),
                'details': [
                    f"Protocol: {protocol}",
                    f"Host: {listener_data.get('ip', '')}",
                    f"Port: {listener_data.get('port', '')}",
                    f"GET Profile: {listener_data.get('get_profile', 'default-get')}",
                    f"POST Profile: {listener_data.get('post_profile', 'default-post')}",
                    f"Response Profile: {listener_data.get('server_response_profile', 'default-response')}"
                ]
            }
        # Filter out empty details
        listener['details'] = [d for d in listener['details'] if d]

        self.add_listener_row(listener)
        self.table.resizeColumnsToContents()

    def remove_listener_row(self, listener_name):
        """Remove a listener row from the table by name."""
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == listener_name:
                self.table.removeRow(row)
                break
