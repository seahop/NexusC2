# floating_status_indicator.py
from PyQt6.QtWidgets import QWidget
from PyQt6.QtCore import QTimer, Qt, pyqtSlot, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QPainter, QColor, QBrush, QPen

class FloatingStatusIndicator(QWidget):
    """
    A minimal floating dot indicator for connection status
    Sits in the top-right corner of the parent window
    """
    
    # Status constants
    STATUS_DISCONNECTED = 0
    STATUS_CONNECTING = 1
    STATUS_CONNECTED = 2
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.status = self.STATUS_DISCONNECTED
        
        # Set up the widget
        self.setFixedSize(12, 12)  # Small dot
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        
        # Position in top-right corner (will be repositioned by parent)
        if parent:
            self.reposition()
        
        # Timer for pulsing animation when connecting
        self.pulse_timer = QTimer()
        self.pulse_timer.timeout.connect(self.update_pulse)
        self.pulse_opacity = 1.0
        self.pulse_direction = -0.05
        
        # Hover tooltip
        self.setToolTip("Disconnected")
        
    def reposition(self):
        """Reposition the dot in the top-right corner of parent"""
        if self.parent():
            parent_width = self.parent().width()
            # Position 10px from right edge, 10px from top
            self.move(parent_width - 22, 10)
    
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Determine color based on status
        if self.status == self.STATUS_CONNECTED:
            color = QColor(0, 200, 0)  # Green
            painter.setOpacity(1.0)
        elif self.status == self.STATUS_CONNECTING:
            color = QColor(255, 200, 0)  # Yellow
            painter.setOpacity(self.pulse_opacity)
        else:  # DISCONNECTED
            color = QColor(200, 0, 0)  # Red
            painter.setOpacity(1.0)
        
        # Draw outer ring (subtle border)
        painter.setPen(QPen(QColor(0, 0, 0, 50), 1))
        painter.setBrush(QBrush(color))
        painter.drawEllipse(1, 1, 10, 10)
        
        # Draw inner glow effect for connected state
        if self.status == self.STATUS_CONNECTED:
            painter.setPen(Qt.PenStyle.NoPen)
            glow_color = QColor(0, 255, 0, 30)
            painter.setBrush(QBrush(glow_color))
            painter.drawEllipse(0, 0, 12, 12)
        
    def set_connected(self):
        """Set status to connected"""
        self.status = self.STATUS_CONNECTED
        self.pulse_timer.stop()
        self.setToolTip("Connected to server")
        self.update()
        
    def set_disconnected(self):
        """Set status to disconnected"""
        self.status = self.STATUS_DISCONNECTED
        self.pulse_timer.stop()
        self.setToolTip("Disconnected from server")
        self.update()
        
    def set_connecting(self):
        """Set status to connecting/reconnecting"""
        self.status = self.STATUS_CONNECTING
        self.pulse_timer.start(50)  # Pulse every 50ms
        self.setToolTip("Connecting to server...")
        self.update()
        
    def update_pulse(self):
        """Update pulsing animation for connecting state"""
        self.pulse_opacity += self.pulse_direction
        if self.pulse_opacity <= 0.3:
            self.pulse_opacity = 0.3
            self.pulse_direction = 0.05
        elif self.pulse_opacity >= 1.0:
            self.pulse_opacity = 1.0
            self.pulse_direction = -0.05
        self.update()
        
    @pyqtSlot(bool, str)
    def on_connection_status(self, connected, message):
        """Handle connection status updates from WebSocket thread"""
        if connected:
            self.set_connected()
        else:
            if "reconnect" in message.lower() or "connecting" in message.lower():
                self.set_connecting()
            else:
                self.set_disconnected()