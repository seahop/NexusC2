# widgets/downloads.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget,
                           QTableWidgetItem, QHeaderView, QMenu, QMessageBox,
                           QFileDialog)
from PyQt6.QtCore import pyqtSlot, Qt, QThread, pyqtSignal
from datetime import datetime
import os
import json
import base64
import asyncio


class FileAssemblyWorker(QThread):
    """Worker thread for assembling downloaded files without blocking GUI."""
    finished = pyqtSignal(str, bool, str)  # filename, success, message

    def __init__(self, filename, chunks, folder):
        super().__init__()
        self.filename = filename
        self.chunks = chunks
        self.folder = folder

    def run(self):
        """Assemble file in background thread with streaming base64 decode."""
        try:
            sorted_chunks = sorted(self.chunks, key=lambda x: x[0])
            filepath = os.path.join(self.folder, self.filename)

            # Stream decode and write chunks to avoid memory spike
            with open(filepath, 'wb') as f:
                for _, chunk_data in sorted_chunks:
                    # Decode each chunk individually instead of holding all in memory
                    decoded_chunk = base64.b64decode(chunk_data)
                    f.write(decoded_chunk)
                    # Clear reference to allow GC
                    del decoded_chunk

            self.finished.emit(self.filename, True,
                             f"File downloaded successfully to {filepath}")
        except Exception as e:
            self.finished.emit(self.filename, False,
                             f"Failed to save file: {str(e)}")


class DownloadsWidget(QWidget):
    def __init__(self, ws_thread=None):
        super().__init__()
        self.ws_thread = ws_thread
        self.initUI()
        
        # Connect to websocket signals if thread exists
        if self.ws_thread:
            self.ws_thread.downloads_update.connect(self.update_downloads)
            self.ws_thread.download_chunk.connect(self.handle_download_chunk)
        
        # Track current downloads
        self.current_downloads = {}
        self.download_folder = None
        self.assembly_workers = {}  # Track active worker threads  

    def initUI(self):
        layout = QVBoxLayout()
        
        # Create table widget
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Filename', 'Size', 'Timestamp'])
        
        # Set table properties
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        
        # Enable context menu
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        layout.addWidget(self.table)
        self.setLayout(layout)

    def format_size(self, size_in_bytes):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.2f} {unit}"
            size_in_bytes /= 1024.0
        return f"{size_in_bytes:.2f} TB"

    @pyqtSlot(list)
    def update_downloads(self, downloads):
        """Update the table with downloads from the manifest."""
        self.table.setRowCount(0)  # Clear existing rows
        
        for download in downloads:
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            
            # Set Filename
            filename_item = QTableWidgetItem(download['filename'])
            self.table.setItem(row_position, 0, filename_item)
            
            # Set Size
            size_item = QTableWidgetItem(self.format_size(download['size']))
            self.table.setItem(row_position, 1, size_item)
            
            # Set Timestamp
            timestamp_item = QTableWidgetItem(download['timestamp'])
            self.table.setItem(row_position, 2, timestamp_item)
        
        self.table.resizeColumnsToContents()

    def show_context_menu(self, position):
        row = self.table.rowAt(position.y())
        if row >= 0:  # Only show menu if we clicked on a row
            menu = QMenu()
            download_action = menu.addAction("Download")
            
            # Get global position for menu
            global_pos = self.table.viewport().mapToGlobal(position)
            
            # Show menu and get selected action
            action = menu.exec(global_pos)
            
            if action == download_action:
                self.download_file(row)

    def download_file(self, row):
        filename = self.table.item(row, 0).text()
        
        # Prompt the user to select a download folder
        self.download_folder = QFileDialog.getExistingDirectory(
            self, 
            "Select Download Folder"
        )
        
        if not self.download_folder:
            QMessageBox.warning(self, "No Folder Selected", "Download folder not selected.")
            return

        # Initialize tracking for this download
        self.current_downloads[filename] = {
            'chunks': [],
            'total_chunks': 0,
            'received_chunks': 0,
            'folder': self.download_folder
        }
        
        # Send download request to server
        if self.ws_thread and self.ws_thread.is_connected():
            request = {
                "type": "request_file_download",
                "data": {
                    "filename": filename
                }
            }
            self.ws_thread.request_file_download_sync(json.dumps(request))
        else:
            QMessageBox.warning(self, "Error", "Not connected to server")

    def handle_download_chunk(self, chunk_data):
        """Handle incoming file chunks and acknowledge receipt."""
        try:
            filename = chunk_data.get('filename')
            chunk_num = chunk_data.get('chunk_num')
            total_chunks = chunk_data.get('total_chunks')
            data = chunk_data.get('data')  # Base64 encoded

            if filename not in self.current_downloads:
                self.current_downloads[filename] = {
                    'chunks': [],
                    'total_chunks': total_chunks,
                    'received_chunks': 0,
                    'folder': self.download_folder  # Store the folder path when initializing
                }

            download = self.current_downloads[filename]
            download['chunks'].append((chunk_num, data))
            download['received_chunks'] += 1

            # Acknowledge chunk receipt
            ack_message = {
                "type": "chunk_ack",
                "data": {
                    "filename": filename,
                    "chunk_num": chunk_num
                }
            }
            asyncio.run_coroutine_threadsafe(
                self.ws_thread.ws_client.send_message(json.dumps(ack_message)),
                self.ws_thread.loop
            )

            # Check if all chunks are received
            if download['received_chunks'] == total_chunks:
                # Pass the folder from the stored download info
                self.assemble_file(filename, download, download['folder'])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error handling file chunk: {e}")

    def assemble_file(self, filename, download, folder):
        """Start file assembly in worker thread."""
        # Create worker thread for file assembly
        worker = FileAssemblyWorker(filename, download['chunks'], folder)
        worker.finished.connect(self.on_assembly_complete)
        self.assembly_workers[filename] = worker
        worker.start()

    def on_assembly_complete(self, filename, success, message):
        """Handle completion of file assembly from worker thread."""
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Error", message)

        # Clean up
        if filename in self.current_downloads:
            del self.current_downloads[filename]
        if filename in self.assembly_workers:
            del self.assembly_workers[filename]

    def set_ws_thread(self, ws_thread):
        """Update websocket thread reference"""
        self.ws_thread = ws_thread
        if self.ws_thread:
            self.ws_thread.downloads_update.connect(self.update_downloads)
            self.ws_thread.download_chunk.connect(self.handle_download_chunk)