# client/src/gui/widgets/terminal/command_history.py

class CommandHistory:
    """Handle command history for navigation with up/down arrows"""
    
    def __init__(self, max_history=100):
        self.history = []
        self.max_history = max_history
        self.current_index = -1
        self.temp_current = ""  # Store current incomplete command
        
    def add_command(self, command):
        """Add a command to history"""
        # Don't add empty commands or duplicates of the last command
        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
            # Limit history size
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]
        self.reset_position()
    
    def get_previous(self, current_text=""):
        """Get previous command in history"""
        if not self.history:
            return current_text
            
        # If we're at the beginning of history navigation, save current text
        if self.current_index == -1:
            self.temp_current = current_text
            
        if self.current_index < len(self.history) - 1:
            self.current_index += 1
            return self.history[-(self.current_index + 1)]
        
        return self.history[0] if self.history else current_text
    
    def get_next(self, current_text=""):
        """Get next command in history"""
        if self.current_index > 0:
            self.current_index -= 1
            return self.history[-(self.current_index + 1)]
        elif self.current_index == 0:
            self.current_index = -1
            return self.temp_current
        
        return current_text
    
    def reset_position(self):
        """Reset history navigation position"""
        self.current_index = -1
        self.temp_current = ""
    
    def get_filtered_history(self, prefix):
        """Get history items that start with the given prefix"""
        if not prefix:
            return self.history
        return [cmd for cmd in self.history if cmd.startswith(prefix)]
    
    def clear(self):
        """Clear command history"""
        self.history = []
        self.reset_position()