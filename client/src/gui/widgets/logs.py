#logs.py
from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtCore import QMetaObject, Qt, Q_ARG, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QTextCursor
from datetime import datetime

class LogsWidget(QTextEdit):
    # Signal for thread-safe log updates
    _log_signal = pyqtSignal(str)

    # Maximum number of lines to keep in the log buffer
    MAX_LOG_LINES = 5000

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self._line_count = 0
        # Connect signal to slot for thread-safe updates
        self._log_signal.connect(self._do_append, Qt.ConnectionType.QueuedConnection)

    @pyqtSlot(str)
    def _do_append(self, formatted_message):
        """Slot that actually appends text - always runs on GUI thread"""
        self.append(formatted_message)
        self._line_count += 1
        self._trim_if_needed()

    def _trim_if_needed(self):
        """Trim old lines if we exceed the maximum buffer size"""
        if self._line_count > self.MAX_LOG_LINES:
            # Remove oldest 20% of lines when limit is reached
            lines_to_remove = self.MAX_LOG_LINES // 5
            cursor = QTextCursor(self.document())
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            for _ in range(lines_to_remove):
                cursor.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            self._line_count -= lines_to_remove

    def add_log(self, message):
        """Thread-safe method to add a log message"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        formatted = f"[{timestamp}] {message}"

        # Check if we're on the main GUI thread
        app = QApplication.instance()
        if app and QThread.currentThread() != app.thread():
            # We're on a different thread - emit signal for thread-safe update
            self._log_signal.emit(formatted)
        else:
            # We're on the GUI thread - can call directly
            self.append(formatted)
            self._line_count += 1
            self._trim_if_needed()
