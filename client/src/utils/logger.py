"""
Centralized logging configuration for the C2 client.
Includes crash logging and log rotation for debugging intermittent issues.
"""
import logging
import logging.handlers
import sys
import traceback
import threading
from pathlib import Path
from datetime import datetime

# Log directory setup
LOG_DIR = Path.home() / '.nexus' / 'logs'
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Log file paths
MAIN_LOG_FILE = LOG_DIR / 'client.log'
CRASH_LOG_FILE = LOG_DIR / 'crash.log'

# Create logger
logger = logging.getLogger('c2_client')
logger.setLevel(logging.DEBUG)

# Create formatters
standard_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] %(filename)s:%(lineno)d - %(funcName)s() - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Create console handler with formatting
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)  # Only INFO and above to console by default
console_handler.setFormatter(standard_formatter)
logger.addHandler(console_handler)

# Create rotating file handler for main logs (10MB max, keep 5 backups)
try:
    file_handler = logging.handlers.RotatingFileHandler(
        MAIN_LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # All levels to file
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)
except Exception as e:
    print(f"Could not create main log file: {e}", file=sys.stderr)

# Create separate crash log file handler (append mode, no rotation for crash investigation)
crash_logger = logging.getLogger('c2_client.crash')
crash_logger.setLevel(logging.ERROR)
try:
    crash_handler = logging.FileHandler(CRASH_LOG_FILE, mode='a', encoding='utf-8')
    crash_handler.setLevel(logging.ERROR)
    crash_handler.setFormatter(detailed_formatter)
    crash_logger.addHandler(crash_handler)
except Exception as e:
    print(f"Could not create crash log file: {e}", file=sys.stderr)


def flush_logs():
    """Force flush all log handlers - call before potential crash points"""
    for handler in logger.handlers:
        handler.flush()
    for handler in crash_logger.handlers:
        handler.flush()


def log_exception(exc_type, exc_value, exc_traceback):
    """
    Log an exception with full traceback.
    Use this as sys.excepthook to catch uncaught exceptions.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        # Don't log keyboard interrupts as crashes
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    # Format the exception
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    tb_text = ''.join(tb_lines)

    # Log to main logger
    logger.critical(f"Uncaught exception:\n{tb_text}")

    # Log to crash log with additional context
    crash_logger.error(
        f"\n{'='*60}\n"
        f"CRASH REPORT - {datetime.now().isoformat()}\n"
        f"{'='*60}\n"
        f"Exception Type: {exc_type.__name__}\n"
        f"Exception Value: {exc_value}\n"
        f"Thread: {threading.current_thread().name}\n"
        f"{'='*60}\n"
        f"Traceback:\n{tb_text}"
        f"{'='*60}\n"
    )

    # Ensure logs are written
    flush_logs()

    # Call the default hook to print to stderr as well
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def log_thread_exception(args):
    """
    Log exceptions from threads (for threading.excepthook).
    """
    tb_text = ''.join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))

    logger.critical(f"Uncaught exception in thread '{args.thread.name}':\n{tb_text}")

    crash_logger.error(
        f"\n{'='*60}\n"
        f"THREAD CRASH REPORT - {datetime.now().isoformat()}\n"
        f"{'='*60}\n"
        f"Thread Name: {args.thread.name}\n"
        f"Exception Type: {args.exc_type.__name__}\n"
        f"Exception Value: {args.exc_value}\n"
        f"{'='*60}\n"
        f"Traceback:\n{tb_text}"
        f"{'='*60}\n"
    )

    flush_logs()


def install_exception_hooks():
    """
    Install global exception hooks to capture crashes.
    Call this early in main() to catch all uncaught exceptions.
    """
    sys.excepthook = log_exception
    threading.excepthook = log_thread_exception
    logger.info("Exception hooks installed - crashes will be logged to disk")


def set_log_level(level):
    """Set the logging level dynamically"""
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(level)
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.setLevel(level)


def get_logger(name=None):
    """Get a logger instance"""
    if name:
        return logging.getLogger(f'c2_client.{name}')
    return logger


def get_log_file_paths():
    """Return paths to log files for user reference"""
    return {
        'main': MAIN_LOG_FILE,
        'crash': CRASH_LOG_FILE
    }
