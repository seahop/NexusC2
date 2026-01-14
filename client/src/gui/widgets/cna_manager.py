# cna_manager.py
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
from .cna_interpreter import CNAInterpreter

# Set up logging for CNA script load failures
def _get_cna_log_path():
    """Get the path to the CNA log file in the config directory"""
    config_dir = Path.home() / '.nexus'
    config_dir.mkdir(exist_ok=True)
    return config_dir / 'cna_startup.log'

class CNAManager:
    """Global manager for CNA scripts shared across all agents with persistence support"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if not self.initialized:
            self.loaded_scripts = []  # List of successfully loaded script paths
            self.commands = {}
            self.bof_commands = {}
            self.aliases = {}
            self.state_db = None  # Will be set by main_window
            self.startup_errors = []  # Track startup load errors
            self.initialized = True

    def set_database(self, db):
        """Set the database reference for persistence"""
        self.state_db = db

    def load_script(self, script_path: str, persist: bool = True) -> bool:
        """Load a CNA script globally with optional persistence

        Args:
            script_path: Path to the CNA script file
            persist: If True, save to database for future sessions

        Returns:
            True if script loaded successfully, False otherwise
        """
        # Check if file exists first
        if not os.path.exists(script_path):
            error_msg = f"Script file not found: {script_path}"
            self._log_error(script_path, error_msg)
            if self.state_db and persist:
                self.state_db.update_cna_script_error(script_path, error_msg)
            return False

        # Check if already loaded
        if script_path in self.loaded_scripts:
            print(f"CNAManager: Script already loaded: {script_path}")
            return True

        try:
            interpreter = CNAInterpreter()
            if interpreter.load_cna_script(script_path):
                self.loaded_scripts.append(script_path)
                self.commands.update(interpreter.commands)
                self.aliases.update(interpreter.aliases)

                # Extract BOF commands
                for cmd_name, cmd in interpreter.commands.items():
                    if cmd.bof_path:
                        self.bof_commands[cmd_name] = {
                            'name': cmd.name,
                            'description': cmd.description,
                            'synopsis': cmd.synopsis,
                            'bof_path': cmd.bof_path,
                            'alias': interpreter.aliases.get(cmd_name)
                        }

                # Persist to database if requested
                if persist and self.state_db:
                    self.state_db.add_cna_script(script_path)
                    self.state_db.clear_cna_script_error(script_path)

                print(f"CNAManager: Successfully loaded script: {script_path}")
                return True
            else:
                error_msg = "Script parsing failed (check script syntax)"
                self._log_error(script_path, error_msg)
                if self.state_db:
                    self.state_db.update_cna_script_error(script_path, error_msg)
                return False

        except Exception as e:
            error_msg = f"Exception during load: {str(e)}"
            self._log_error(script_path, error_msg)
            if self.state_db:
                self.state_db.update_cna_script_error(script_path, error_msg)
            return False

    def unload_script(self, script_path: str, remove_from_db: bool = True) -> bool:
        """Unload a CNA script and optionally remove from persistence

        Args:
            script_path: Path to the CNA script file
            remove_from_db: If True, remove from database so it won't load on next startup

        Returns:
            True if script unloaded successfully, False otherwise
        """
        if script_path not in self.loaded_scripts:
            # Check if it's stored as a directory (old behavior)
            script_dir = os.path.dirname(script_path)
            if script_dir in self.loaded_scripts:
                self.loaded_scripts.remove(script_dir)
            else:
                return False
        else:
            self.loaded_scripts.remove(script_path)

        # Remove from database if requested
        if remove_from_db and self.state_db:
            self.state_db.remove_cna_script(script_path)

        # Note: Command cleanup is handled by the interpreter's unload_script method
        # The manager just tracks the global state
        print(f"CNAManager: Unloaded script: {script_path}")
        return True

    def load_persisted_scripts(self) -> dict:
        """Load all persisted CNA scripts from database on startup

        Returns:
            Dictionary with 'loaded' (list of paths) and 'failed' (list of {path, error} dicts)
        """
        result = {'loaded': [], 'failed': []}

        if not self.state_db:
            print("CNAManager: No database configured, skipping persisted script load")
            return result

        scripts = self.state_db.get_cna_scripts(enabled_only=True)

        if not scripts:
            print("CNAManager: No persisted CNA scripts to load")
            return result

        print(f"CNAManager: Loading {len(scripts)} persisted CNA script(s)...")

        for script_info in scripts:
            script_path = script_info['script_path']

            # Don't persist again since it's already in DB
            try:
                success = self.load_script(script_path, persist=False)
                if success:
                    result['loaded'].append(script_path)
                    # Clear any previous error
                    self.state_db.clear_cna_script_error(script_path)
                else:
                    error = "Failed to load script"
                    result['failed'].append({'path': script_path, 'error': error})
            except Exception as e:
                error = str(e)
                result['failed'].append({'path': script_path, 'error': error})
                self._log_error(script_path, error)
                self.state_db.update_cna_script_error(script_path, error)

        # Log summary
        if result['loaded']:
            print(f"CNAManager: Successfully loaded {len(result['loaded'])} script(s)")
        if result['failed']:
            print(f"CNAManager: Failed to load {len(result['failed'])} script(s)")
            self._write_startup_log(result['failed'])

        return result

    def _log_error(self, script_path: str, error: str):
        """Log an error for a script load failure"""
        timestamp = datetime.now().isoformat()
        error_entry = {
            'timestamp': timestamp,
            'script_path': script_path,
            'error': error
        }
        self.startup_errors.append(error_entry)
        print(f"CNAManager ERROR [{timestamp}]: {script_path} - {error}")

    def _write_startup_log(self, failed_scripts: list):
        """Write startup failures to log file"""
        log_path = _get_cna_log_path()
        try:
            with open(log_path, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"CNA Script Startup Log - {datetime.now().isoformat()}\n")
                f.write(f"{'='*60}\n")
                for item in failed_scripts:
                    f.write(f"FAILED: {item['path']}\n")
                    f.write(f"  Error: {item['error']}\n")
                f.write("\n")
            print(f"CNAManager: Startup errors logged to: {log_path}")
        except Exception as e:
            print(f"CNAManager: Failed to write log file: {e}")

    def get_startup_errors(self) -> list:
        """Get list of errors from the last startup"""
        return self.startup_errors.copy()

    def clear_startup_errors(self):
        """Clear the startup errors list"""
        self.startup_errors.clear()

    def get_log_path(self) -> Path:
        """Get the path to the CNA log file"""
        return _get_cna_log_path()

    def apply_to_terminal(self, terminal):
        """Apply all loaded CNA scripts to a terminal"""
        if not hasattr(terminal.command_validator, 'cna_commands'):
            terminal.command_validator.cna_commands = {}
        if not hasattr(terminal.command_validator, 'cna_bof_commands'):
            terminal.command_validator.cna_bof_commands = {}

        # Copy commands
        terminal.command_validator.cna_commands = self.commands.copy()
        terminal.command_validator.cna_bof_commands = self.bof_commands.copy()

        # Update interpreter
        terminal.command_handler.cna_interpreter.commands = self.commands.copy()
        terminal.command_handler.cna_interpreter.aliases = self.aliases.copy()
        terminal.command_handler.cna_interpreter.loaded_scripts = self.loaded_scripts.copy()

    def get_persisted_scripts(self, include_disabled: bool = False) -> list:
        """Get list of all persisted scripts from database

        Args:
            include_disabled: If True, include disabled scripts too

        Returns:
            List of script info dictionaries
        """
        if not self.state_db:
            return []
        return self.state_db.get_cna_scripts(enabled_only=not include_disabled)

    def disable_script(self, script_path: str) -> bool:
        """Disable a script (won't load on next startup but stays in DB)"""
        if self.state_db:
            return self.state_db.set_cna_script_enabled(script_path, False)
        return False

    def enable_script(self, script_path: str) -> bool:
        """Enable a previously disabled script"""
        if self.state_db:
            return self.state_db.set_cna_script_enabled(script_path, True)
        return False
