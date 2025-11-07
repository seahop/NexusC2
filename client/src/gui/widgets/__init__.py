from .logs import LogsWidget
from .terminal import TerminalWidget, AgentTerminal
from .agent_tree import AgentTreeWidget

def __init__(self, agent_name, agent_guid=None, ws_thread=None):
    # Existing init code...
    if ws_thread:
        self.ws_thread = ws_thread
        if hasattr(ws_thread, 'username'):
            self.command_buffer.set_username(ws_thread.username)