# cna_manager.py
from typing import Dict, List
from .cna_interpreter import CNAInterpreter

class CNAManager:
    """Global manager for CNA scripts shared across all agents"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if not self.initialized:
            self.loaded_scripts = []
            self.commands = {}
            self.bof_commands = {}
            self.aliases = {}
            self.initialized = True
    
    def load_script(self, script_path: str) -> bool:
        """Load a CNA script globally"""
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
            return True
        return False
    
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