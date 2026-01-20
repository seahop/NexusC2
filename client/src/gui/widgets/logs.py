#logs.py
from PyQt6.QtWidgets import QTextEdit
from PyQt6.QtCore import QMetaObject, Qt, Q_ARG, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import QApplication
from datetime import datetime

class LogsWidget(QTextEdit):
    # Signal for thread-safe log updates
    _log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        # Connect signal to slot for thread-safe updates
        self._log_signal.connect(self._do_append, Qt.ConnectionType.QueuedConnection)

    @pyqtSlot(str)
    def _do_append(self, formatted_message):
        """Slot that actually appends text - always runs on GUI thread"""
        self.append(formatted_message)

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
