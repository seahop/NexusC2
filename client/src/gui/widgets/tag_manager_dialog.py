# client/src/gui/widgets/tag_manager_dialog.py
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QListWidget,
                              QPushButton, QLineEdit, QLabel, QColorDialog,
                              QListWidgetItem, QMessageBox, QWidget)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
import json
import asyncio


class TagManagerDialog(QDialog):
    """Dialog for managing agent tags"""

    def __init__(self, agent_guid, agent_name, current_tags, ws_thread, parent=None):
        super().__init__(parent)
        self.agent_guid = agent_guid
        self.agent_name = agent_name
        self.current_tags = current_tags.copy() if current_tags else []
        self.ws_thread = ws_thread

        self.setWindowTitle(f"Manage Tags - {agent_name}")
        self.setMinimumWidth(400)
        self.setMinimumHeight(300)

        self.setup_ui()
        self.load_current_tags()

    def setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout()

        # Header
        header = QLabel(f"Tags for agent: {self.agent_name}")
        header.setStyleSheet("font-weight: bold; font-size: 12pt;")
        layout.addWidget(header)

        # Tag list
        self.tag_list = QListWidget()
        self.tag_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.tag_list)

        # Add new tag section
        add_layout = QHBoxLayout()
        add_label = QLabel("New tag:")
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("Enter tag name...")
        self.tag_input.returnPressed.connect(self.add_tag)

        # Color picker button
        self.color_button = QPushButton("Color")
        self.color_button.setFixedWidth(60)
        self.selected_color = "#4A90E2"  # Default blue
        self.update_color_button()
        self.color_button.clicked.connect(self.choose_color)

        add_button = QPushButton("Add Tag")
        add_button.clicked.connect(self.add_tag)

        add_layout.addWidget(add_label)
        add_layout.addWidget(self.tag_input)
        add_layout.addWidget(self.color_button)
        add_layout.addWidget(add_button)
        layout.addLayout(add_layout)

        # Action buttons
        action_layout = QHBoxLayout()

        self.remove_button = QPushButton("Remove Selected")
        self.remove_button.clicked.connect(self.remove_tag)
        self.remove_button.setEnabled(False)

        self.tag_list.itemSelectionChanged.connect(
            lambda: self.remove_button.setEnabled(len(self.tag_list.selectedItems()) > 0)
        )

        action_layout.addWidget(self.remove_button)
        action_layout.addStretch()

        layout.addLayout(action_layout)

        # Dialog buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        save_button = QPushButton("Save & Close")
        save_button.clicked.connect(self.save_and_close)
        save_button.setDefault(True)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)

        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def update_color_button(self):
        """Update the color button appearance"""
        self.color_button.setStyleSheet(
            f"background-color: {self.selected_color}; "
            f"color: {'white' if self.is_dark_color(self.selected_color) else 'black'};"
        )

    def is_dark_color(self, hex_color):
        """Check if a color is dark (for text contrast)"""
        try:
            color = QColor(hex_color)
            # Calculate perceived brightness
            brightness = (color.red() * 299 + color.green() * 587 + color.blue() * 114) / 1000
            return brightness < 128
        except:
            return False

    def choose_color(self):
        """Open color picker dialog"""
        color = QColorDialog.getColor(QColor(self.selected_color), self, "Choose Tag Color")
        if color.isValid():
            self.selected_color = color.name()
            self.update_color_button()

    def load_current_tags(self):
        """Load current tags into the list"""
        self.tag_list.clear()
        for tag in self.current_tags:
            self.add_tag_to_list(tag['name'], tag['color'])

    def add_tag_to_list(self, tag_name, tag_color):
        """Add a tag to the visual list"""
        item = QListWidgetItem(tag_name)
        item.setData(Qt.ItemDataRole.UserRole, tag_color)

        # Set background color
        item.setBackground(QColor(tag_color))

        # Set text color based on brightness
        text_color = QColor("white") if self.is_dark_color(tag_color) else QColor("black")
        item.setForeground(text_color)

        self.tag_list.addItem(item)

    def add_tag(self):
        """Add a new tag"""
        tag_name = self.tag_input.text().strip()

        if not tag_name:
            QMessageBox.warning(self, "Invalid Tag", "Tag name cannot be empty.")
            return

        # Check for duplicates
        for tag in self.current_tags:
            if tag['name'].lower() == tag_name.lower():
                QMessageBox.warning(self, "Duplicate Tag", f"Tag '{tag_name}' already exists.")
                return

        # Add to current tags
        new_tag = {"name": tag_name, "color": self.selected_color}
        self.current_tags.append(new_tag)

        # Add to visual list
        self.add_tag_to_list(tag_name, self.selected_color)

        # Clear input
        self.tag_input.clear()

        # Reset color to default
        self.selected_color = "#4A90E2"
        self.update_color_button()

    def remove_tag(self):
        """Remove the selected tag"""
        selected_items = self.tag_list.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        tag_name = item.text()

        # Confirm removal
        reply = QMessageBox.question(
            self, "Remove Tag",
            f"Remove tag '{tag_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Remove from current tags
            self.current_tags = [tag for tag in self.current_tags if tag['name'] != tag_name]

            # Remove from visual list
            row = self.tag_list.row(item)
            self.tag_list.takeItem(row)

    def save_and_close(self):
        """Save tags and close dialog"""
        if not self.ws_thread or not self.ws_thread.is_connected():
            QMessageBox.warning(self, "Not Connected", "Not connected to server. Cannot save tags.")
            return

        try:
            # Send tag updates to server
            # We need to send individual add/remove messages for each change
            # For simplicity, we'll just send the final state and let the server handle it

            # For now, send add_tag for each tag (server will handle duplicates)
            for tag in self.current_tags:
                add_msg = {
                    "type": "add_tag",
                    "data": {
                        "agent_id": self.agent_guid,
                        "tag_name": tag['name'],
                        "tag_color": tag['color']
                    }
                }

                asyncio.run_coroutine_threadsafe(
                    self.ws_thread.ws_client.send_message(json.dumps(add_msg)),
                    self.ws_thread.loop
                )

            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save tags: {e}")

    def get_tags(self):
        """Get the current tags"""
        return self.current_tags
