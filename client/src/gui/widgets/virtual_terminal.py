from PyQt6.QtWidgets import QScrollArea, QWidget, QVBoxLayout, QLabel, QApplication, QTextEdit
from PyQt6.QtCore import Qt, pyqtSlot, QTimer, pyqtSignal
from PyQt6.QtGui import QWheelEvent, QTextCursor, QTextOption
import math

class VirtualTerminal(QScrollArea):
    """
    Optimized virtual terminal using QTextEdit for smooth, stable scrolling.
    This approach avoids chunk management issues and provides buttery smooth scrolling.
    """
    
    # Performance tuning constants
    MAX_LINES = 10000  # Maximum buffer size
    AUTO_SCROLL_THRESHOLD = 10  # Pixels from bottom to trigger auto-scroll
    SCROLL_SPEED_MULTIPLIER = 1  # Mouse wheel sensitivity (reduced for smoother control)
    
    # Signals for external communication
    scrollPositionChanged = pyqtSignal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._initialize_ui()
        self._initialize_content_management()
        self._initialize_scrolling()
        
    def _initialize_ui(self):
        """Set up the UI components using QTextEdit for stability"""
        # Create the text edit widget
        self.text_widget = QTextEdit()
        self.text_widget.setReadOnly(True)
        self.text_widget.setWordWrapMode(QTextOption.WrapMode.NoWrap)
        
        # Set font
        font = self.text_widget.font()
        font.setFamily("Consolas" if "Consolas" in QApplication.font().families() else "Monospace")
        font.setPointSize(10)
        self.text_widget.setFont(font)
        
        # Set as the scroll area's widget
        self.setWidget(self.text_widget)
        self.setWidgetResizable(True)
        
        # Keep scrollbars visible
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.text_widget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.text_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        
        # Styling
        self.text_widget.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: none;
                selection-background-color: #3399ff;
                selection-color: #d4d4d4;
                padding: 5px;
            }
            QScrollBar:vertical {
                background-color: #2d2d2d;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #555555;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #666666;
            }
            QScrollBar::handle:vertical:pressed {
                background-color: #777777;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

    def set_theme(self, theme="dark"):
        """Set the terminal theme"""
        
        # Define all theme stylesheets
        themes = {
            "dark": """
                QTextEdit {
                    background-color: #1e1e1e;
                    color: #d4d4d4;
                    border: none;
                    selection-background-color: #3399ff;
                    selection-color: #d4d4d4;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #2d2d2d;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #555555;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #666666;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #777777;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "light": """
                QTextEdit {
                    background-color: #ffffff;
                    color: #000000;
                    border: none;
                    selection-background-color: #0078d4;
                    selection-color: #ffffff;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #f0f0f0;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #c0c0c0;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #a0a0a0;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #808080;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "dracula": """
                QTextEdit {
                    background-color: #282a36;
                    color: #f8f8f2;
                    border: none;
                    selection-background-color: #bd93f9;
                    selection-color: #282a36;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #44475a;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #6272a4;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #7282b4;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #bd93f9;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "monokai": """
                QTextEdit {
                    background-color: #272822;
                    color: #f8f8f2;
                    border: none;
                    selection-background-color: #a6e22e;
                    selection-color: #272822;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #3e3d32;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #75715e;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #858175;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #a6e22e;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "nord": """
                QTextEdit {
                    background-color: #2e3440;
                    color: #eceff4;
                    border: none;
                    selection-background-color: #88c0d0;
                    selection-color: #2e3440;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #3b4252;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #4c566a;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #5c667a;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #88c0d0;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "solarized_dark": """
                QTextEdit {
                    background-color: #002b36;
                    color: #839496;
                    border: none;
                    selection-background-color: #268bd2;
                    selection-color: #fdf6e3;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #073642;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #586e75;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #687e85;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #268bd2;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "gruvbox": """
                QTextEdit {
                    background-color: #282828;
                    color: #ebdbb2;
                    border: none;
                    selection-background-color: #fabd2f;
                    selection-color: #282828;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #3c3836;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #665c54;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #766c64;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #fabd2f;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,
            
            "one_dark": """
                QTextEdit {
                    background-color: #282c34;
                    color: #abb2bf;
                    border: none;
                    selection-background-color: #61afef;
                    selection-color: #282c34;
                    padding: 5px;
                }
                QScrollBar:vertical {
                    background-color: #21252b;
                    width: 12px;
                    border-radius: 6px;
                }
                QScrollBar::handle:vertical {
                    background-color: #3e4451;
                    border-radius: 6px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #4e5461;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #61afef;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    height: 0px;
                }
            """,

            "hotdog_stand": """
                QTextEdit {
                    background-color: #FF0000;
                    color: #FFFFFF;
                    border: 2px inset #000000;
                    selection-background-color: #000000;
                    selection-color: #FFFFFF;
                    padding: 5px;
                    font-weight: bold;
                }
                QScrollBar:vertical {
                    background-color: #FFFF00;
                    width: 16px;
                    border: 1px solid #000000;
                }
                QScrollBar::handle:vertical {
                    background-color: #FF0000;
                    border: 2px outset #FF0000;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background-color: #CC0000;
                }
                QScrollBar::handle:vertical:pressed {
                    background-color: #000000;
                }
                QScrollBar::add-line:vertical,
                QScrollBar::sub-line:vertical {
                    background-color: #FF0000;
                    border: 2px outset #FF0000;
                    height: 16px;
                }
            """
        }
        
        # Apply the selected theme, default to dark if not found
        stylesheet = themes.get(theme, themes["dark"])
        self.text_widget.setStyleSheet(stylesheet)

    def _initialize_content_management(self):
        """Initialize content management"""
        self.all_content = []
        self.read_only = True
        self._is_updating = False  # Flag to prevent recursive updates
        
    def _initialize_scrolling(self):
        """Initialize scrolling system"""
        # Auto-scroll state
        self.auto_scroll = True
        self.user_has_scrolled = False
        
        # Get the actual scrollbar from QTextEdit
        self.scrollbar = self.text_widget.verticalScrollBar()
        
        # Connect scroll events
        self.scrollbar.valueChanged.connect(self._on_scroll_value_changed)
        self.scrollbar.rangeChanged.connect(self._on_scroll_range_changed)
        
        # Override text widget's wheel event
        self.text_widget.wheelEvent = self._handle_wheel_event
        
        # Set up document for smooth updates
        self.text_widget.document().setMaximumBlockCount(self.MAX_LINES)
        
    def _on_scroll_value_changed(self, value):
        """Handle scroll events"""
        if self._is_updating:
            return
            
        max_value = self.scrollbar.maximum()
        if max_value == 0:
            return
        
        # Check if we're at the bottom
        at_bottom = value >= (max_value - self.AUTO_SCROLL_THRESHOLD)
        
        # Update auto-scroll state based on position
        if at_bottom and not self.user_has_scrolled:
            self.auto_scroll = True
        elif not self._is_updating:
            # User has manually scrolled
            if value < (max_value - self.AUTO_SCROLL_THRESHOLD):
                self.auto_scroll = False
                
        self.scrollPositionChanged.emit(value)
        
    def _on_scroll_range_changed(self, min_val, max_val):
        """Handle scrollbar range changes"""
        if self._is_updating:
            return
            
        # If auto-scrolling and content was added, scroll to bottom
        if self.auto_scroll and max_val > 0:
            QTimer.singleShot(0, lambda: self._scroll_to_bottom())
            
    def _handle_wheel_event(self, event: QWheelEvent):
        """Custom wheel event handling"""
        delta = event.angleDelta().y()
        
        # If scrolling up, disable auto-scroll
        if delta > 0:  # Scrolling up
            current_value = self.scrollbar.value()
            max_value = self.scrollbar.maximum()
            # Only disable if we're moving away from bottom
            if current_value < (max_value - self.AUTO_SCROLL_THRESHOLD):
                self.auto_scroll = False
                self.user_has_scrolled = True
        else:  # Scrolling down
            # Check if we'll reach the bottom
            current_value = self.scrollbar.value()
            max_value = self.scrollbar.maximum()
            # Estimate scroll amount
            scroll_amount = abs(delta) // 2
            if current_value + scroll_amount >= (max_value - self.AUTO_SCROLL_THRESHOLD):
                self.auto_scroll = True
                self.user_has_scrolled = False
        
        # Let QTextEdit handle the actual scrolling
        QTextEdit.wheelEvent(self.text_widget, event)
        
    def _scroll_to_bottom(self):
        """Scroll to the bottom of content"""
        if self._is_updating:
            return
        self.scrollbar.setValue(self.scrollbar.maximum())
        
    def setText(self, text):
        """Set new content and scroll to bottom"""
        self._is_updating = True
        
        # Store content as lines
        self.all_content = text.splitlines() if text else []
        
        # Trim if exceeds maximum
        if len(self.all_content) > self.MAX_LINES:
            self.all_content = self.all_content[-self.MAX_LINES:]
        
        # Update the text widget
        self.text_widget.clear()
        self.text_widget.setPlainText('\n'.join(self.all_content))
        
        # Always start at bottom for new content
        self.auto_scroll = True
        self.user_has_scrolled = False
        
        self._is_updating = False
        
        # Force scroll to bottom
        QTimer.singleShot(10, self._scroll_to_bottom)
        
    def append(self, text):
        """Append new content with smooth scrolling"""
        if not text:
            return
            
        self._is_updating = True
        
        # Store current scroll state
        scrollbar = self.text_widget.verticalScrollBar()
        old_max = scrollbar.maximum()
        old_value = scrollbar.value()
        
        # Check if we're at bottom before adding content
        was_at_bottom = old_value >= (old_max - self.AUTO_SCROLL_THRESHOLD) if old_max > 0 else True
        
        # If we have no content and are appending, start at bottom
        if not self.all_content:
            was_at_bottom = True
            self.auto_scroll = True
        
        # Add new lines to our buffer
        new_lines = text.splitlines()
        self.all_content.extend(new_lines)
        
        # Check if we need to trim old content
        needs_full_refresh = False
        if len(self.all_content) > self.MAX_LINES:
            lines_to_remove = len(self.all_content) - self.MAX_LINES
            self.all_content = self.all_content[lines_to_remove:]
            needs_full_refresh = True
        
        # Update display
        if needs_full_refresh:
            # Only do full refresh if we trimmed content
            self.text_widget.setPlainText('\n'.join(self.all_content))
        else:
            # Smooth append without clearing - prevents flash
            cursor = self.text_widget.textCursor()
            
            # Block signals to prevent flashing
            self.text_widget.blockSignals(True)
            
            # Move to end and insert
            cursor.movePosition(QTextCursor.MoveOperation.End)
            if self.text_widget.document().characterCount() > 1:  # Not empty
                cursor.insertText('\n')
            cursor.insertText('\n'.join(new_lines))
            
            # Re-enable signals
            self.text_widget.blockSignals(False)
        
        self._is_updating = False
        
        # Handle scrolling based on previous position
        if was_at_bottom:
            # Stay at bottom
            self.auto_scroll = True
            # Immediate scroll to bottom, no delay needed for append
            scrollbar.setValue(scrollbar.maximum())
        else:
            # Maintain position - the cursor operations shouldn't have moved us
            self.auto_scroll = False
        
    def clear(self):
        """Clear all content and reset state"""
        self._is_updating = True
        self.all_content = []
        self.text_widget.clear()
        self.auto_scroll = True
        self.user_has_scrolled = False
        self._is_updating = False
        
    def toPlainText(self):
        """Get all content as plain text"""
        return self.text_widget.toPlainText()
        
    def setLineWrapMode(self, mode):
        """Set line wrap mode"""
        if mode:
            self.text_widget.setWordWrapMode(QTextOption.WrapMode.WrapAnywhere)
        else:
            self.text_widget.setWordWrapMode(QTextOption.WrapMode.NoWrap)
            
    def setFontFamily(self, family):
        """Set the font family"""
        font = self.text_widget.font()
        font.setFamily(family)
        self.text_widget.setFont(font)
        
    def setReadOnly(self, value):
        """Set read-only mode"""
        self.read_only = value
        self.text_widget.setReadOnly(value)
        
    def scroll_to_bottom(self):
        """Public method to scroll to bottom"""
        self.auto_scroll = True
        self._scroll_to_bottom()
        
    def scroll_to_top(self):
        """Scroll to top of content"""
        self.auto_scroll = False
        self.scrollbar.setValue(0)
        
    def get_visible_text(self):
        """Get currently visible text"""
        # Get the viewport's visible region
        cursor_top = self.text_widget.cursorForPosition(self.text_widget.viewport().rect().topLeft())
        cursor_bottom = self.text_widget.cursorForPosition(self.text_widget.viewport().rect().bottomLeft())
        
        cursor_top.setPosition(cursor_bottom.position(), QTextCursor.MoveMode.KeepAnchor)
        return cursor_top.selectedText()
        
    def refresh_display(self):
        """Force a complete refresh of the display"""
        self._is_updating = True
        current_text = '\n'.join(self.all_content)
        self.text_widget.setPlainText(current_text)
        self._is_updating = False
        
        if self.auto_scroll:
            QTimer.singleShot(10, self._scroll_to_bottom)
            
    def setVerticalScrollBarPolicy(self, policy):
        """Override to apply to text widget instead"""
        if hasattr(self, 'text_widget'):
            self.text_widget.setVerticalScrollBarPolicy(policy)
        else:
            super().setVerticalScrollBarPolicy(policy)
            
    def setHorizontalScrollBarPolicy(self, policy):
        """Override to apply to text widget instead"""
        if hasattr(self, 'text_widget'):
            self.text_widget.setHorizontalScrollBarPolicy(policy)
        else:
            super().setHorizontalScrollBarPolicy(policy)
            
    def verticalScrollBar(self):
        """Return the text widget's scrollbar"""
        if hasattr(self, 'text_widget'):
            return self.text_widget.verticalScrollBar()
        return super().verticalScrollBar()