"""Tests for the response handler (gui/widgets/terminal/handlers/response_handler.py).

Focus areas from code-review fixes:
  - BOF chunk TTL cleanup (stale chunks removed after 300 seconds)
  - Chunk reassembly logic
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


# Patch dependencies before import
with patch.dict("sys.modules", {
    "utils.logger": MagicMock(get_logger=MagicMock(return_value=MagicMock())),
    "utils.error_codes": MagicMock(translate_code=lambda x: x),
}):
    from gui.widgets.terminal.handlers.response_handler import ResponseHandler


def _make_terminal():
    """Create a mock terminal object with required attributes."""
    terminal = MagicMock()
    terminal.agent_guid = "agent-123"
    terminal.command_buffer = MagicMock()
    terminal.file_uploader = MagicMock()
    terminal.bof_handler = MagicMock()
    terminal.inline_assembly_handler = MagicMock()
    return terminal


class TestBOFChunkTTL(unittest.TestCase):
    """BOF chunk TTL must be 300 seconds, and stale chunks must be cleaned."""

    def test_ttl_constant_is_300(self):
        self.assertEqual(ResponseHandler.BOF_CHUNK_TTL_SECONDS, 300)

    def test_stale_chunks_cleaned_by_timestamp(self):
        """Chunks older than TTL are removed by _cleanup_stale_bof_chunks."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        # Simulate a stale chunk entry (6 minutes old)
        old_time = (datetime.now() - timedelta(seconds=400)).isoformat()
        handler.bof_chunks["old_cmd"] = {
            "chunks": {1: "data"},
            "total": 2,
            "timestamp": old_time,
        }

        # And a fresh chunk entry (10 seconds old)
        recent_time = (datetime.now() - timedelta(seconds=10)).isoformat()
        handler.bof_chunks["new_cmd"] = {
            "chunks": {1: "data"},
            "total": 2,
            "timestamp": recent_time,
        }

        handler._cleanup_stale_bof_chunks()

        self.assertNotIn("old_cmd", handler.bof_chunks,
                          "Stale chunk should have been cleaned up")
        self.assertIn("new_cmd", handler.bof_chunks,
                       "Recent chunk should remain")

    def test_cleanup_removes_unparseable_timestamps(self):
        """Entries with unparseable timestamps are treated as stale."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        handler.bof_chunks["bad_ts"] = {
            "chunks": {1: "data"},
            "total": 2,
            "timestamp": "not-a-date",
        }

        handler._cleanup_stale_bof_chunks()

        self.assertNotIn("bad_ts", handler.bof_chunks,
                          "Entry with unparseable timestamp should be cleaned up")

    def test_cleanup_noop_when_empty(self):
        """Cleanup on empty bof_chunks should not raise."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)
        handler.bof_chunks = {}
        handler._cleanup_stale_bof_chunks()  # Should not raise

    def test_all_stale_entries_removed(self):
        """If all entries are stale, bof_chunks should be empty after cleanup."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        old = (datetime.now() - timedelta(seconds=600)).isoformat()
        for i in range(5):
            handler.bof_chunks[f"cmd_{i}"] = {
                "chunks": {1: "data"},
                "total": 2,
                "timestamp": old,
            }

        handler._cleanup_stale_bof_chunks()
        self.assertEqual(len(handler.bof_chunks), 0)


class TestBOFChunkReassembly(unittest.TestCase):
    """_handle_bof_chunk must correctly reassemble multi-chunk output."""

    def test_single_chunk_returns_immediately(self):
        """A single 1/1 chunk should return the content right away."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        output = "[BOF Chunk 1/1]\nHello from BOF"
        result = handler._handle_bof_chunk(output, "cmd-1", "2026-10-17T12:00:00Z")

        self.assertIsNotNone(result)
        self.assertIn("Hello from BOF", result)

    def test_multi_chunk_waits_for_all(self):
        """With 2 chunks, first returns None, second returns combined output."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        chunk1 = "[BOF Chunk 1/2]\nPart one"
        chunk2 = "[BOF Chunk 2/2]\nPart two"

        result1 = handler._handle_bof_chunk(chunk1, "cmd-2", "2026-10-17T12:00:00Z")
        self.assertIsNone(result1, "Should return None while waiting for more chunks")

        result2 = handler._handle_bof_chunk(chunk2, "cmd-2", "2026-10-17T12:00:00Z")
        self.assertIsNotNone(result2, "Should return assembled output")
        self.assertIn("Part one", result2)
        self.assertIn("Part two", result2)

    def test_cleanup_called_before_processing(self):
        """_handle_bof_chunk must call _cleanup_stale_bof_chunks."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)
        handler._cleanup_stale_bof_chunks = MagicMock()

        handler._handle_bof_chunk("[BOF Chunk 1/1]\ntest", "cmd-3", "ts")
        handler._cleanup_stale_bof_chunks.assert_called_once()

    def test_chunks_cleaned_up_after_complete(self):
        """After all chunks are received, the entry should be removed from bof_chunks."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        handler._handle_bof_chunk("[BOF Chunk 1/1]\ndata", "cmd-4", "ts")
        self.assertNotIn("cmd-4", handler.bof_chunks)

    def test_invalid_chunk_format_returns_as_is(self):
        """Non-chunk-formatted output should be returned unchanged."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        result = handler._handle_bof_chunk("not a chunk", "cmd-5", "ts")
        self.assertEqual(result, "not a chunk")


class TestIsBOFChunk(unittest.TestCase):
    """_is_bof_chunk regex must match the expected pattern."""

    def setUp(self):
        self.terminal = _make_terminal()
        self.handler = ResponseHandler(self.terminal)

    def test_matches_valid_chunk_header(self):
        self.assertTrue(self.handler._is_bof_chunk("[BOF Chunk 1/3]\ndata"))

    def test_matches_large_numbers(self):
        self.assertTrue(self.handler._is_bof_chunk("[BOF Chunk 42/100]\ndata"))

    def test_rejects_non_chunk(self):
        self.assertFalse(self.handler._is_bof_chunk("regular output"))

    def test_rejects_partial_match(self):
        self.assertFalse(self.handler._is_bof_chunk("[BOF Chunk ]\ndata"))


class TestHandleCommandResult(unittest.TestCase):
    """handle_command_result dispatches correctly."""

    def test_skips_wrong_agent(self):
        """Results for a different agent should be ignored."""
        terminal = _make_terminal()
        terminal.agent_guid = "agent-A"
        handler = ResponseHandler(terminal)

        handler.handle_command_result({
            "agent_id": "agent-B",
            "output": "should be ignored",
        })

        # command_buffer.add_output should NOT have been called
        terminal.command_buffer.add_output.assert_not_called()

    def test_accepts_matching_agent(self):
        """Results for this agent should be processed."""
        terminal = _make_terminal()
        terminal.agent_guid = "agent-A"
        handler = ResponseHandler(terminal)

        handler.handle_command_result({
            "agent_id": "agent-A",
            "output": "hello world",
            "timestamp": "2026-10-17T12:00:00Z",
        })

        terminal.command_buffer.add_output.assert_called_once()

    def test_queued_status_displays_output_as_is(self):
        """Status 'queued' should display output without modification."""
        terminal = _make_terminal()
        handler = ResponseHandler(terminal)

        handler.handle_command_result({
            "agent_id": "agent-123",
            "output": "Command queued for agent",
            "status": "queued",
            "timestamp": "2026-10-17T12:00:00Z",
        })

        terminal.command_buffer.add_output.assert_called_once()
        call_arg = terminal.command_buffer.add_output.call_args[0][0]
        self.assertEqual(call_arg["output"], "Command queued for agent")


if __name__ == "__main__":
    unittest.main()
