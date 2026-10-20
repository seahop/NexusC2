"""Tests for the WebSocket client (utils/websocket_client.py).

Focus areas from code-review fixes:
  - TLS context uses check_hostname=True and CERT_REQUIRED
  - message_metadata has max size enforcement (1000 entries, evicts oldest half)
  - Thread safety of metadata operations
"""

import json
import ssl
import threading
import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Patch heavy dependencies before the module under test is imported
# ---------------------------------------------------------------------------
with patch.dict("sys.modules", {
    "websockets": MagicMock(),
    "websockets.exceptions": MagicMock(),
    "gui.widgets": MagicMock(),
    "utils.logger": MagicMock(get_logger=MagicMock(return_value=MagicMock())),
    "utils.database": MagicMock(),
}):
    from utils.websocket_client import WebSocketClient


class TestTLSContext(unittest.TestCase):
    """Verify the TLS context is constructed securely."""

    def test_tls_check_hostname_and_cert_required_in_source(self):
        """connect() source must set check_hostname=True and verify_mode=CERT_REQUIRED.

        We verify the source code directly because the mock import chain
        prevents patching ssl.SSLContext at the module level.
        """
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "src" / "utils" / "websocket_client.py").read_text()
        self.assertIn("check_hostname = True", src,
                       "connect() must set check_hostname = True")
        self.assertIn("ssl.CERT_REQUIRED", src,
                       "connect() must set verify_mode = ssl.CERT_REQUIRED")
        self.assertIn("ssl.PROTOCOL_TLS_CLIENT", src,
                       "connect() must use PROTOCOL_TLS_CLIENT")

    def test_tls_settings_not_disabled(self):
        """Source must NOT contain insecure overrides."""
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "src" / "utils" / "websocket_client.py").read_text()
        self.assertNotIn("check_hostname = False", src,
                          "check_hostname must not be set to False")
        self.assertNotIn("CERT_NONE", src,
                          "verify_mode must not be set to CERT_NONE")


class TestMessageMetadataEviction(unittest.TestCase):
    """message_metadata must not grow unbounded."""

    def setUp(self):
        self.client = WebSocketClient()

    def test_max_size_is_1000(self):
        self.assertEqual(self.client._metadata_max_size, 1000)

    def test_evicts_oldest_half_when_exceeding_max(self):
        """When metadata exceeds 1000 entries the oldest half is removed."""
        # Fill exactly to the max -- no eviction yet
        for i in range(self.client._metadata_max_size):
            msg = json.dumps({"type": "test", "seq": i})
            self.client.queue_message(msg)

        self.assertEqual(len(self.client.message_metadata), self.client._metadata_max_size)

        # One more push triggers eviction
        overflow_msg = json.dumps({"type": "test", "seq": 9999})
        self.client.queue_message(overflow_msg)

        # After eviction: original 1001 entries minus 500 (oldest half) = 501
        self.assertLessEqual(len(self.client.message_metadata), self.client._metadata_max_size)
        # Specifically, 1001 - 500 = 501
        self.assertEqual(len(self.client.message_metadata), 501)

        # The overflow message should still be present (it was the newest)
        self.assertIn(overflow_msg, self.client.message_metadata)

    def test_oldest_entries_are_evicted_first(self):
        """Eviction removes from the front of the OrderedDict (oldest)."""
        first_msg = json.dumps({"type": "first", "seq": 0})
        self.client.queue_message(first_msg)

        for i in range(1, self.client._metadata_max_size + 1):
            msg = json.dumps({"type": "filler", "seq": i})
            self.client.queue_message(msg)

        # first_msg should have been evicted (it was the oldest)
        self.assertNotIn(first_msg, self.client.message_metadata)

    def test_metadata_is_ordered_dict(self):
        """Metadata container must be an OrderedDict for FIFO eviction."""
        self.assertIsInstance(self.client.message_metadata, OrderedDict)


class TestMetadataThreadSafety(unittest.TestCase):
    """Concurrent queue_message calls must not corrupt metadata."""

    def test_concurrent_queue_message(self):
        client = WebSocketClient()
        errors = []

        def worker(start, count):
            try:
                for i in range(start, start + count):
                    msg = json.dumps({"type": "concurrent", "seq": i})
                    client.queue_message(msg)
            except Exception as e:
                errors.append(e)

        threads = []
        per_thread = 200
        num_threads = 5
        for t in range(num_threads):
            th = threading.Thread(target=worker, args=(t * per_thread, per_thread))
            threads.append(th)

        for th in threads:
            th.start()
        for th in threads:
            th.join()

        self.assertEqual(errors, [], f"Threads raised exceptions: {errors}")
        # Metadata size must not exceed max (eviction keeps it bounded)
        self.assertLessEqual(len(client.message_metadata), client._metadata_max_size)

    def test_metadata_lock_exists_and_is_threading_lock(self):
        client = WebSocketClient()
        self.assertIsInstance(client._metadata_lock, type(threading.Lock()))


class TestMetadataCaching(unittest.TestCase):
    """queue_message must cache correct metadata tuples."""

    def test_regular_message_metadata(self):
        client = WebSocketClient()
        msg = json.dumps({"type": "heartbeat"})
        client.queue_message(msg)

        meta = client.message_metadata[msg]
        msg_type, is_high, is_chunked, chunk_info = meta
        self.assertEqual(msg_type, "heartbeat")
        self.assertFalse(is_high)
        self.assertFalse(is_chunked)
        self.assertIsNone(chunk_info)

    def test_high_priority_message_metadata(self):
        client = WebSocketClient()
        msg = json.dumps({"type": "agent_command", "data": {}})
        client.queue_message(msg)

        meta = client.message_metadata[msg]
        _, is_high, _, _ = meta
        self.assertTrue(is_high)

    def test_chunked_message_metadata(self):
        client = WebSocketClient()
        msg = json.dumps({
            "type": "agent_command",
            "data": {
                "totalChunks": 5,
                "currentChunk": 2,
                "filename": "payload.o",
            },
        })
        client.queue_message(msg)

        meta = client.message_metadata[msg]
        _, _, is_chunked, chunk_info = meta
        self.assertTrue(is_chunked)
        self.assertEqual(chunk_info["total"], 5)
        self.assertEqual(chunk_info["current"], 2)
        self.assertEqual(chunk_info["filename"], "payload.o")

    def test_malformed_json_gets_unknown_metadata(self):
        client = WebSocketClient()
        bad_msg = "this is not json"
        client.queue_message(bad_msg)

        meta = client.message_metadata[bad_msg]
        msg_type, is_high, is_chunked, chunk_info = meta
        self.assertEqual(msg_type, "unknown")
        self.assertFalse(is_high)
        self.assertFalse(is_chunked)
        self.assertIsNone(chunk_info)


class TestChunkTTL(unittest.TestCase):
    """Verify the chunk TTL configuration."""

    def test_chunk_ttl_is_300_seconds(self):
        client = WebSocketClient()
        self.assertEqual(client.chunk_ttl, 300)


if __name__ == "__main__":
    unittest.main()
