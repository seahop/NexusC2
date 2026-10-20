"""Tests for the BOF handler (gui/widgets/bof_handler.py).

Focus areas from code-review fixes:
  - No duplicate _pack_string method (BOFArgumentParser has exactly one)
  - Correct attribute reference: agent_terminal.command_buffer is used
  - BOFArgumentParser produces correct packed data
"""

import inspect
import struct
import unittest
from unittest.mock import MagicMock, patch

# Patch heavy deps before import
with patch.dict("sys.modules", {
    "utils.logger": MagicMock(get_logger=MagicMock(return_value=MagicMock())),
}):
    from gui.widgets.bof_handler import BOFArgumentParser, BOFHandler, BOFFile


class TestNoDuplicatePackString(unittest.TestCase):
    """BOFArgumentParser must have exactly one _pack_string method.

    A previous bug had _pack_string defined twice in the class, causing the
    first definition to be silently overridden.
    """

    @classmethod
    def _read_source(cls):
        """Read the bof_handler.py source file directly (inspect.getsource
        fails through mock import chains)."""
        import pathlib
        src_path = pathlib.Path(__file__).resolve().parent.parent / "src" / "gui" / "widgets" / "bof_handler.py"
        return src_path.read_text()

    def test_pack_string_defined_once(self):
        """Count _pack_string definitions in source -- must be exactly 1."""
        source = self._read_source()
        count = source.count("def _pack_string(")
        self.assertEqual(
            count, 1,
            f"_pack_string should be defined exactly once, found {count} definition(s)"
        )

    def test_pack_wstring_defined_once(self):
        source = self._read_source()
        count = source.count("def _pack_wstring(")
        self.assertEqual(count, 1)

    def test_all_static_methods_unique(self):
        """No static methods should be duplicated in BOFArgumentParser."""
        source = self._read_source()

        # Extract just the BOFArgumentParser class body
        in_class = False
        method_names = []
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("class BOFArgumentParser"):
                in_class = True
                continue
            if in_class and stripped.startswith("class "):
                break  # Next class
            if in_class and stripped.startswith("def "):
                name = stripped.split("(")[0].replace("def ", "")
                method_names.append(name)

        # Check for duplicates
        seen = set()
        duplicates = set()
        for name in method_names:
            if name in seen:
                duplicates.add(name)
            seen.add(name)

        self.assertEqual(
            duplicates, set(),
            f"Duplicate method definitions found: {duplicates}"
        )


class TestCorrectAttributeReference(unittest.TestCase):
    """BOFHandler must reference agent_terminal.command_buffer, not a wrong path."""

    def test_add_to_history_uses_command_buffer(self):
        """_add_to_history accesses self.agent_terminal.command_buffer."""
        source = inspect.getsource(BOFHandler._add_to_history)
        self.assertIn("self.agent_terminal.command_buffer", source)

    def test_print_info_uses_command_buffer(self):
        source = inspect.getsource(BOFHandler._print_info)
        self.assertIn("self.agent_terminal.command_buffer", source)

    def test_print_error_uses_command_buffer(self):
        source = inspect.getsource(BOFHandler._print_error)
        self.assertIn("self.agent_terminal.command_buffer", source)

    def test_add_to_history_checks_hasattr(self):
        """_add_to_history should check hasattr for command_buffer before access."""
        source = inspect.getsource(BOFHandler._add_to_history)
        self.assertIn("hasattr", source)


class TestBOFArgumentParsing(unittest.TestCase):
    """BOFArgumentParser must produce correct packed output."""

    def test_pack_string(self):
        """_pack_string: 4-byte LE length prefix + UTF-8 data + null."""
        result = BOFArgumentParser._pack_string("ABC")
        # "ABC" + \x00 = 4 bytes
        expected_len = 4
        # First 4 bytes = length in little-endian
        length = struct.unpack("<I", result[:4])[0]
        self.assertEqual(length, expected_len)
        # Data portion
        self.assertEqual(result[4:], b"ABC\x00")

    def test_pack_wstring(self):
        """_pack_wstring: 4-byte LE length prefix + UTF-16LE data + null."""
        result = BOFArgumentParser._pack_wstring("AB")
        # "AB" in UTF-16LE = b'A\x00B\x00' + null b'\x00\x00' = 6 bytes
        expected_len = 6
        length = struct.unpack("<I", result[:4])[0]
        self.assertEqual(length, expected_len)
        self.assertEqual(result[4:], b"A\x00B\x00\x00\x00")

    def test_pack_int32(self):
        result = BOFArgumentParser._pack_int32(42)
        self.assertEqual(result, struct.pack("<i", 42))

    def test_pack_int64(self):
        result = BOFArgumentParser._pack_int64(0x0102030405060708)
        self.assertEqual(result, struct.pack("<q", 0x0102030405060708))

    def test_pack_int16(self):
        result = BOFArgumentParser._pack_int16(256)
        self.assertEqual(result, struct.pack("<h", 256))

    def test_parse_typed_string_arg(self):
        """'-s:hello' should pack as a string."""
        result = BOFArgumentParser.parse_arguments(["-s:hello"])
        expected = BOFArgumentParser._pack_string("hello")
        self.assertEqual(result, expected)

    def test_parse_typed_int_arg(self):
        """'-i:42' should pack as a 32-bit int."""
        result = BOFArgumentParser.parse_arguments(["-i:42"])
        expected = BOFArgumentParser._pack_int32(42)
        self.assertEqual(result, expected)

    def test_parse_plain_string(self):
        """Plain strings (no prefix) are packed as strings."""
        result = BOFArgumentParser.parse_arguments(["testarg"])
        expected = BOFArgumentParser._pack_string("testarg")
        self.assertEqual(result, expected)

    def test_parse_multiple_args(self):
        """Multiple args get concatenated in order."""
        result = BOFArgumentParser.parse_arguments(["-s:foo", "-i:10"])
        expected = BOFArgumentParser._pack_string("foo") + BOFArgumentParser._pack_int32(10)
        self.assertEqual(result, expected)

    def test_dash_without_colon_treated_as_string(self):
        """A dash arg without ':' is treated as a plain string."""
        result = BOFArgumentParser.parse_arguments(["-verbose"])
        expected = BOFArgumentParser._pack_string("-verbose")
        self.assertEqual(result, expected)


class TestBOFHandlerInit(unittest.TestCase):
    """BOFHandler __init__ stores references correctly."""

    def test_stores_ws_client(self):
        ws = MagicMock()
        terminal = MagicMock()
        terminal.agent_guid = "test-guid-123"
        handler = BOFHandler(ws, terminal)
        self.assertIs(handler.ws_client, ws)

    def test_stores_agent_terminal(self):
        ws = MagicMock()
        terminal = MagicMock()
        terminal.agent_guid = "test-guid-123"
        handler = BOFHandler(ws, terminal)
        self.assertIs(handler.agent_terminal, terminal)

    def test_loaded_bofs_starts_empty(self):
        ws = MagicMock()
        terminal = MagicMock()
        terminal.agent_guid = "test-guid-123"
        handler = BOFHandler(ws, terminal)
        self.assertEqual(handler.loaded_bofs, {})

    def test_async_jobs_starts_empty(self):
        ws = MagicMock()
        terminal = MagicMock()
        terminal.agent_guid = "test-guid-123"
        handler = BOFHandler(ws, terminal)
        self.assertEqual(handler.async_jobs, {})


class TestBOFHandlerCommands(unittest.TestCase):
    """BOFHandler.handle_bof_command dispatches correctly."""

    def setUp(self):
        self.ws = MagicMock()
        self.terminal = MagicMock()
        self.terminal.agent_guid = "test-guid-123"
        self.terminal.command_buffer = MagicMock()
        self.terminal.command_buffer.username = "tester"
        self.terminal.command_history = MagicMock()
        self.handler = BOFHandler(self.ws, self.terminal)

    def test_bof_jobs_no_active(self):
        result = self.handler.handle_bof_command("bof-jobs", [])
        self.assertTrue(result)

    def test_bof_list_no_loaded(self):
        result = self.handler.handle_bof_command("bof-list", [])
        self.assertTrue(result)

    def test_bof_unload_not_loaded(self):
        result = self.handler.handle_bof_command("bof-unload", ["nonexistent"])
        self.assertTrue(result)

    def test_unknown_command_returns_false(self):
        result = self.handler.handle_bof_command("bof-nonexistent", [])
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
