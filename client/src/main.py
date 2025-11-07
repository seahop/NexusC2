import sys
import os
import signal
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor
from PyQt6.QtCore import Qt
from gui.main_window import C2ClientGUI

def setup_dark_theme_hints():
    """Set environment variables to hint dark theme to window managers"""
    # For GTK-based window managers (GNOME, XFCE, etc.)
    os.environ['GTK_THEME'] = 'Adwaita:dark'
    # For Qt platform theme
    os.environ['QT_QPA_PLATFORMTHEME'] = 'gtk3'
    # KDE Plasma hint
    os.environ['KDE_SESSION_VERSION'] = '5'

def set_application_dark_palette(app):
    """Set dark palette for the entire application (affects window decorations on Linux)"""
    dark_palette = QPalette()
    
    # Window colors (affects title bar on Linux)
    dark_palette.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    
    # Base colors
    dark_palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    
    # Text colors
    dark_palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    
    # Bright text and links
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    
    # Disabled colors
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(127, 127, 127))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Highlight, QColor(80, 80, 80))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.HighlightedText, QColor(127, 127, 127))
    
    app.setPalette(dark_palette)

def main():
    # Set environment hints BEFORE creating QApplication
    setup_dark_theme_hints()
    
    app = QApplication(sys.argv)
    
    # Set application-wide dark palette (affects Linux window decorations)
    set_application_dark_palette(app)
    
    # Set application style hints
    app.setStyle('Fusion')  # Fusion style works well with dark themes
    
    # Set up signal handler for clean shutdown
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    ex = C2ClientGUI()
    ex.show()
    
    # Use app.exec() instead of sys.exit(app.exec())
    ret = app.exec()
    
    # Ensure clean shutdown
    app.quit()
    
    sys.exit(ret)

if __name__ == '__main__':
    main()