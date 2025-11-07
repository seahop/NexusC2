# client/src/gui/widgets/terminal/tab_completer.py

import os

class TabCompleter:
    """Handle tab completion for commands and file paths"""
    
    def __init__(self, command_validator):
        self.command_validator = command_validator
        self.agent_os = None  # Store agent OS for filtering
        self.completion_candidates = []
        self.completion_index = 0
        self.original_text = ""
        self.completion_prefix = ""
    
    def set_agent_os(self, agent_os):
        """Update the agent's OS for filtering commands"""
        self.agent_os = agent_os
        
    def get_all_commands(self):
        """Get all available commands from various sources, filtered by OS if available"""
        # If we have an agent OS and the validator supports OS filtering, use it
        if self.agent_os and hasattr(self.command_validator, 'get_commands_for_os'):
            return self.command_validator.get_commands_for_os(self.agent_os)
        
        # Otherwise fall back to the original behavior
        commands = set()
        
        # Get commands from validator
        if hasattr(self.command_validator, 'commands'):
            for cmd in self.command_validator.commands.keys():
                # Convert underscore to dash for display
                commands.add(cmd.replace('_', '-'))
        
        # Add BOF commands (only if on Windows or no OS specified)
        if hasattr(self.command_validator, 'bof_commands'):
            if not self.agent_os or self.agent_os.lower() in ['windows', 'win', 'win32', 'win64']:
                commands.update(self.command_validator.bof_commands)
        
        # Add inline assembly commands (only if on Windows or no OS specified)
        if hasattr(self.command_validator, 'inline_assembly_commands'):
            if not self.agent_os or self.agent_os.lower() in ['windows', 'win', 'win32', 'win64']:
                commands.update(self.command_validator.inline_assembly_commands)
        
        return sorted(list(commands))
    
    def get_path_completions(self, partial_path):
        """Get file/directory completions for a partial path"""
        completions = []
        
        # Handle ~ expansion
        if partial_path.startswith('~'):
            partial_path = os.path.expanduser(partial_path)
        
        # Determine the directory and prefix to search
        if os.path.isdir(partial_path):
            # If it's a directory, list its contents
            search_dir = partial_path
            prefix = ""
            base_path = partial_path
            if not base_path.endswith(os.sep):
                base_path += os.sep
        else:
            # Split into directory and file prefix
            search_dir = os.path.dirname(partial_path) or "."
            prefix = os.path.basename(partial_path)
            base_path = os.path.dirname(partial_path)
            if base_path and not base_path.endswith(os.sep):
                base_path += os.sep
        
        # Expand the search directory
        search_dir = os.path.expanduser(search_dir)
        
        try:
            # List directory contents
            if os.path.exists(search_dir) and os.path.isdir(search_dir):
                for item in os.listdir(search_dir):
                    if item.startswith(prefix):
                        full_path = os.path.join(search_dir, item)
                        # Format the completion
                        if base_path:
                            completion = base_path + item
                        else:
                            completion = item
                        
                        # Add trailing slash for directories
                        if os.path.isdir(full_path):
                            completion += os.sep
                        
                        completions.append(completion)
        except (OSError, PermissionError):
            # Handle permission errors gracefully
            pass
        
        return sorted(completions)
    
    def get_completions(self, text, cursor_position):
        """Get completions for the current text and cursor position"""
        # Get the text up to the cursor
        text_before_cursor = text[:cursor_position]
        
        # Split into parts
        parts = text_before_cursor.split()
        
        if not parts:
            # At the beginning, show all commands
            return self.get_all_commands(), "", 0
        
        # Check if the first command is 'help'
        if len(parts) >= 1 and parts[0].lower() == 'help':
            # Handle help command completion
            if len(parts) == 1:
                # Just "help" typed, waiting for a command
                if text_before_cursor.endswith(' '):
                    # "help " - show all commands
                    return self.get_all_commands(), "", 1
                else:
                    # "help" without space - don't complete yet
                    return [], "", 0
            elif len(parts) == 2:
                # "help <partial_command>" - complete the command name
                partial = parts[1].lower()
                commands = self.get_all_commands()
                matches = [cmd for cmd in commands if cmd.startswith(partial)]
                return matches, partial, 1
            else:
                # More than 2 parts after help, no completion needed
                return [], "", 0
        
        # Original logic for non-help commands
        # Determine what we're completing
        if len(parts) == 1:
            # Completing a command
            partial = parts[0].lower()
            commands = self.get_all_commands()
            matches = [cmd for cmd in commands if cmd.startswith(partial)]
            return matches, partial, len(parts) - 1
        else:
            # Completing an argument (likely a file path)
            # Find the current word being completed
            # Handle case where cursor is right after a space
            if text_before_cursor.endswith(' '):
                partial = ""
                word_index = len(parts)
            else:
                partial = parts[-1]
                word_index = len(parts) - 1
            
            # Check if it looks like a path
            if any(sep in partial for sep in ['/', '\\']) or partial.startswith('~') or partial == "." or partial == "..":
                # Complete as path
                completions = self.get_path_completions(partial)
                return completions, partial, word_index
            elif word_index > 0:
                # After a command, try path completion even without separators
                # This allows completing filenames in current directory
                completions = self.get_path_completions(partial)
                if completions:
                    return completions, partial, word_index
            
            return [], partial, word_index
    
    def reset(self):
        """Reset completion state"""
        self.completion_candidates = []
        self.completion_index = 0
        self.original_text = ""
        self.completion_prefix = ""