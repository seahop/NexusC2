#logs.py
from PyQt6.QtWidgets import QTextEdit
from datetime import datetime

class LogsWidget(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
    
    def add_log(self, message):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.append(f"[{timestamp}] {message}")
