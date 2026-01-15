import sys
import os
import signal
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor, QIcon
from PyQt6.QtCore import Qt, qInstallMessageHandler, QtMsgType
from gui.main_window import C2ClientGUI
from utils.logger import get_logger, install_exception_hooks, flush_logs, get_log_file_paths

# Initialize logger early
logger = get_logger('main')

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

def qt_message_handler(msg_type, context, message):
    """Handle Qt messages and log them appropriately"""
    if msg_type == QtMsgType.QtDebugMsg:
        logger.debug(f"Qt: {message}")
    elif msg_type == QtMsgType.QtInfoMsg:
        logger.info(f"Qt: {message}")
    elif msg_type == QtMsgType.QtWarningMsg:
        logger.warning(f"Qt: {message} (file: {context.file}, line: {context.line})")
    elif msg_type == QtMsgType.QtCriticalMsg:
        logger.error(f"Qt Critical: {message} (file: {context.file}, line: {context.line})")
    elif msg_type == QtMsgType.QtFatalMsg:
        logger.critical(f"Qt Fatal: {message} (file: {context.file}, line: {context.line})")
        flush_logs()


def main():
    # Install exception hooks FIRST to catch any crashes during startup
    install_exception_hooks()

    log_paths = get_log_file_paths()
    logger.info(f"Nexus client starting - logs at: {log_paths['main']}")
    logger.info(f"Crash logs at: {log_paths['crash']}")

    # Install Qt message handler to capture Qt-level errors
    qInstallMessageHandler(qt_message_handler)

    # Set environment hints BEFORE creating QApplication
    setup_dark_theme_hints()

    # Set application name and desktop file name for Linux taskbar integration
    # This must be done BEFORE creating QApplication
    QApplication.setApplicationName("Nexus")
    QApplication.setDesktopFileName("nexus")
    QApplication.setApplicationDisplayName("Nexus")

    # Set WM_CLASS for proper GNOME/Linux taskbar icon matching
    # This helps GNOME associate the window with a .desktop file
    os.environ['RESOURCE_NAME'] = 'nexus'

    logger.debug("Creating QApplication")
    app = QApplication(sys.argv)

    # Set application-wide icon (required for Linux taskbar)
    icon_path = Path(__file__).parent / 'gui' / 'resources' / 'n.png'
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Set application-wide dark palette (affects Linux window decorations)
    set_application_dark_palette(app)

    # Set application style hints
    app.setStyle('Fusion')  # Fusion style works well with dark themes

    # Set up signal handler for clean shutdown
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    logger.debug("Creating main window")
    ex = C2ClientGUI()
    ex.show()
    logger.info("Main window displayed, entering event loop")

    # Use app.exec() instead of sys.exit(app.exec())
    ret = app.exec()

    logger.info(f"Application exiting with code: {ret}")
    flush_logs()

    # Ensure clean shutdown
    app.quit()

    sys.exit(ret)

if __name__ == '__main__':
    main()