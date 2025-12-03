# notifications.py
# Desktop and audio notifications for C2 client events

from PyQt6.QtWidgets import (QWidget, QLabel, QHBoxLayout, QVBoxLayout,
                              QPushButton, QGraphicsOpacityEffect, QApplication)
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import QObject, pyqtSignal, QTimer, QUrl, Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtMultimedia import QSoundEffect
from pathlib import Path
import json
import subprocess
import sys


class ToastNotification(QWidget):
    """In-app toast notification widget that slides in from the top-right."""

    clicked = pyqtSignal(str)  # Emits agent_guid when clicked
    dismissed = pyqtSignal()

    def __init__(self, title, message, agent_guid=None, parent=None):
        super().__init__(parent)
        self.agent_guid = agent_guid
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool |
                           Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)

        self.setup_ui(title, message)
        self.setup_animation()

        # Auto-dismiss after 8 seconds
        self.dismiss_timer = QTimer(self)
        self.dismiss_timer.setSingleShot(True)
        self.dismiss_timer.timeout.connect(self.fade_out)
        self.dismiss_timer.start(8000)

    def setup_ui(self, title, message):
        """Setup the toast UI."""
        self.setFixedWidth(350)
        self.setStyleSheet("""
            QWidget#toast_container {
                background-color: #2d2d2d;
                border: 2px solid #4CAF50;
                border-radius: 8px;
            }
            QLabel#title {
                color: #4CAF50;
                font-weight: bold;
                font-size: 13px;
            }
            QLabel#message {
                color: #e0e0e0;
                font-size: 12px;
            }
            QPushButton#close_btn {
                background: transparent;
                color: #888;
                border: none;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton#close_btn:hover {
                color: #fff;
            }
        """)

        # Main container
        container = QWidget()
        container.setObjectName("toast_container")
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(12, 10, 8, 10)

        # Content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setObjectName("title")
        content_layout.addWidget(title_label)

        msg_label = QLabel(message)
        msg_label.setObjectName("message")
        msg_label.setWordWrap(True)
        content_layout.addWidget(msg_label)

        if self.agent_guid:
            click_hint = QLabel("Click to open terminal")
            click_hint.setStyleSheet("color: #666; font-size: 10px; font-style: italic;")
            content_layout.addWidget(click_hint)

        container_layout.addLayout(content_layout, 1)

        # Close button
        close_btn = QPushButton("×")
        close_btn.setObjectName("close_btn")
        close_btn.setFixedSize(24, 24)
        close_btn.clicked.connect(self.fade_out)
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        container_layout.addWidget(close_btn, 0, Qt.AlignmentFlag.AlignTop)

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(container)

        self.adjustSize()

    def setup_animation(self):
        """Setup fade-in animation."""
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0)

        self.fade_anim = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_anim.setDuration(300)
        self.fade_anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def show_toast(self):
        """Show the toast with animation."""
        # Position in top-right of screen
        screen = QApplication.primaryScreen().geometry()
        x = screen.width() - self.width() - 20
        y = 50
        self.move(x, y)

        self.show()
        self.fade_anim.setStartValue(0)
        self.fade_anim.setEndValue(1)
        self.fade_anim.start()

    def fade_out(self):
        """Fade out and close."""
        self.dismiss_timer.stop()
        self.fade_anim.setStartValue(1)
        self.fade_anim.setEndValue(0)
        self.fade_anim.finished.connect(self._on_fade_out_finished)
        self.fade_anim.start()

    def _on_fade_out_finished(self):
        """Called when fade out completes."""
        self.dismissed.emit()
        self.close()
        self.deleteLater()

    def mousePressEvent(self, event):
        """Handle click on the toast."""
        if event.button() == Qt.MouseButton.LeftButton and self.agent_guid:
            self.clicked.emit(self.agent_guid)
            self.fade_out()
        super().mousePressEvent(event)

    def enterEvent(self, event):
        """Pause auto-dismiss when hovering."""
        self.dismiss_timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """Resume auto-dismiss when not hovering."""
        self.dismiss_timer.start(3000)  # Shorter timeout after hover
        super().leaveEvent(event)


class NotificationManager(QObject):
    """Manages desktop and audio notifications for the C2 client."""

    # Signal emitted when notification is clicked
    notification_clicked = pyqtSignal(str)  # agent_guid

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent
        self.settings = self._load_settings()

        # Initialize sound effect
        self.sound_effect = None
        self._setup_sound()

        # Track active toast notifications
        self.active_toasts = []

        # Track pending notification for legacy compatibility
        self.pending_notification_guid = None

    def _load_settings(self):
        """Load notification settings from config file."""
        config_file = Path.home() / '.nexus' / 'settings.json'
        defaults = {
            'notifications_enabled': True,
            'notification_toast_enabled': True,
            'notification_native_enabled': True,
            'notification_sound_enabled': True,
            'notification_sound_volume': 70,  # 0-100
        }

        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    saved = json.load(f)
                    # Merge with defaults
                    for key, value in defaults.items():
                        if key not in saved:
                            saved[key] = value
                    return saved
            except:
                pass
        return defaults

    def reload_settings(self):
        """Reload settings from disk (call after settings are saved)."""
        self.settings = self._load_settings()
        # Update sound volume
        if self.sound_effect:
            self.sound_effect.setVolume(self.settings.get('notification_sound_volume', 70) / 100.0)

    def _setup_sound(self):
        """Setup sound effect for notifications."""
        self.sound_effect = QSoundEffect(self)

        # Look for notification sound file
        sound_paths = [
            Path(__file__).parent / 'sounds' / 'notification.wav',
            Path(__file__).parent.parent / 'sounds' / 'notification.wav',
            Path(__file__).parent.parent.parent / 'sounds' / 'notification.wav',
            Path.home() / '.nexus' / 'sounds' / 'notification.wav',
        ]

        sound_file = None
        for path in sound_paths:
            if path.exists():
                sound_file = path
                break

        if sound_file:
            self.sound_effect.setSource(QUrl.fromLocalFile(str(sound_file)))
            self.sound_effect.setVolume(self.settings.get('notification_sound_volume', 70) / 100.0)
            print(f"NotificationManager: Loaded sound from {sound_file}")
        else:
            # Create default sound directory and generate a simple beep
            self._generate_default_sound()

    def _generate_default_sound(self):
        """Generate a simple notification sound if none exists."""
        import struct
        import wave

        sounds_dir = Path.home() / '.nexus' / 'sounds'
        sounds_dir.mkdir(parents=True, exist_ok=True)
        sound_file = sounds_dir / 'notification.wav'

        if not sound_file.exists():
            try:
                # Generate a simple two-tone notification beep
                sample_rate = 44100
                duration = 0.15  # seconds per tone

                # Two tones: 880Hz (A5) and 1100Hz
                frequencies = [880, 1100]
                samples = []

                import math
                for freq in frequencies:
                    for i in range(int(sample_rate * duration)):
                        # Sine wave with envelope
                        t = i / sample_rate
                        envelope = min(1.0, min(t / 0.01, (duration - t) / 0.02))  # Attack/release
                        value = int(envelope * 16000 * math.sin(2 * math.pi * freq * t))
                        samples.append(struct.pack('<h', value))

                # Write WAV file
                with wave.open(str(sound_file), 'w') as wav:
                    wav.setnchannels(1)
                    wav.setsampwidth(2)
                    wav.setframerate(sample_rate)
                    wav.writeframes(b''.join(samples))

                print(f"NotificationManager: Generated default sound at {sound_file}")
            except Exception as e:
                print(f"NotificationManager: Failed to generate sound: {e}")
                return

        # Load the generated sound
        self.sound_effect.setSource(QUrl.fromLocalFile(str(sound_file)))
        self.sound_effect.setVolume(self.settings.get('notification_sound_volume', 70) / 100.0)

    def notify_new_agent(self, agent_data):
        """Show notification for a new agent connection."""
        if not self.settings.get('notifications_enabled', True):
            return

        guid = agent_data.get('guid', 'Unknown')
        hostname = agent_data.get('hostname', 'Unknown')
        username = agent_data.get('username', 'Unknown')
        ip = agent_data.get('ip', 'Unknown')
        os_name = agent_data.get('os', 'Unknown')

        title = "New Agent Connected"
        message = f"{hostname} ({ip})\n{username} - {os_name}"

        # Store GUID for click handling
        self.pending_notification_guid = guid

        # Show in-app toast notification if enabled
        if self.settings.get('notification_toast_enabled', True):
            self._show_toast_notification(title, message, guid)

        # Show native notification if enabled
        if self.settings.get('notification_native_enabled', True):
            self._show_native_notification(title, message.replace('\n', ' - '))

        # Play sound
        if self.settings.get('notification_sound_enabled', True):
            self._play_sound()

    def _show_toast_notification(self, title, message, agent_guid=None):
        """Show an in-app toast notification."""
        toast = ToastNotification(title, message, agent_guid)

        # Connect signals
        toast.clicked.connect(self._on_toast_clicked)
        toast.dismissed.connect(lambda: self._on_toast_dismissed(toast))

        # Stack toasts if multiple
        y_offset = 50
        for existing_toast in self.active_toasts:
            if existing_toast.isVisible():
                y_offset = existing_toast.y() + existing_toast.height() + 10

        self.active_toasts.append(toast)
        toast.show_toast()

        # Adjust position if stacked
        if y_offset > 50:
            screen = QApplication.primaryScreen().geometry()
            toast.move(screen.width() - toast.width() - 20, y_offset)

    def _on_toast_clicked(self, agent_guid):
        """Handle toast click."""
        self.notification_clicked.emit(agent_guid)
        if self.pending_notification_guid == agent_guid:
            self.pending_notification_guid = None

    def _on_toast_dismissed(self, toast):
        """Handle toast dismissal."""
        if toast in self.active_toasts:
            self.active_toasts.remove(toast)

    def _show_native_notification(self, title, message):
        """Try to show a native OS notification."""
        if sys.platform == 'linux':
            # Try notify-send (works on most Linux desktops)
            try:
                subprocess.Popen(
                    ['notify-send', '-a', 'Nexus C2', '-u', 'normal', title, message],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except FileNotFoundError:
                pass  # notify-send not available
        # On other platforms, we rely on the toast notification

    def _play_sound(self):
        """Play the notification sound."""
        if self.sound_effect and self.sound_effect.status() == QSoundEffect.Status.Ready:
            self.sound_effect.play()

    def dismiss_pending(self):
        """Dismiss any pending notification without action."""
        self.pending_notification_guid = None
        # Dismiss all active toasts
        for toast in self.active_toasts[:]:
            toast.fade_out()

    def on_main_window_focused(self):
        """Called when main window gains focus - auto-dismiss pending notifications."""
        # Don't auto-dismiss toasts when focusing - let user interact with them
        # Just clear the pending GUID
        if self.pending_notification_guid:
            print(f"NotificationManager: Window focused, clearing pending GUID")
            self.pending_notification_guid = None

    def test_notification(self):
        """Send a test notification (useful for settings testing)."""
        if self.settings.get('notification_toast_enabled', True):
            self._show_toast_notification(
                "Test Notification",
                "This is a test notification from Nexus C2.",
                None
            )
        if self.settings.get('notification_native_enabled', True):
            self._show_native_notification(
                "Test Notification",
                "This is a test notification from Nexus C2."
            )
        if self.settings.get('notification_sound_enabled', True):
            self._play_sound()

    def cleanup(self):
        """Clean up resources."""
        # Dismiss all toasts
        for toast in self.active_toasts[:]:
            toast.close()
        self.active_toasts.clear()
