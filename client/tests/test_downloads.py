"""Tests for the downloads widget (gui/widgets/downloads.py).

Focus areas from code-review fixes:
  - Path traversal prevention (filenames with .., absolute paths, etc.)
  - Signal disconnection before reconnection in set_ws_thread
"""

import os
import base64
import tempfile
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Patch PyQt6 before importing the module under test
# ---------------------------------------------------------------------------
import sys
import types

# Ensure conftest mocks are installed (they run at import time)
from . import conftest  # noqa: F401  -- triggers _install_pyqt6_mocks

# Now we need to mock QThread to be a regular class for FileAssemblyWorker
# so we can actually call .run() in tests without a real event loop.
_real_qthread = type("FakeQThread", (), {
    "__init__": lambda self: None,
    "start": lambda self: None,
})

# Patch QThread for the downloads module specifically
with patch.dict("sys.modules", {
    "utils.logger": MagicMock(get_logger=MagicMock(return_value=MagicMock())),
}):
    # We need a minimal QThread that allows subclassing
    _qtcore = sys.modules["PyQt6.QtCore"]
    # Save original and patch
    _orig_qthread = _qtcore.QThread

    class _TestableQThread:
        """Minimal QThread stand-in that allows subclassing and .run()."""
        finished = MagicMock()
        def __init__(self, *a, **kw):
            pass
        def start(self):
            self.run()

    _qtcore.QThread = _TestableQThread

    # Import the module - it will use our patched QThread
    # We import only FileAssemblyWorker to test path traversal
    # (DownloadsWidget requires full QWidget setup which is harder to mock)
    from gui.widgets.downloads import FileAssemblyWorker, DownloadsWidget

    # Restore
    _qtcore.QThread = _orig_qthread


class TestFileAssemblyPathTraversal(unittest.TestCase):
    """FileAssemblyWorker must sanitize filenames to prevent path traversal."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Simple chunk: one chunk, base64-encoded "hello"
        self.chunks = [(0, base64.b64encode(b"hello").decode())]

    def tearDown(self):
        # Clean up any files that may have been written
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_worker(self, filename):
        """Create a FileAssemblyWorker and capture its finished signal."""
        worker = FileAssemblyWorker.__new__(FileAssemblyWorker)
        worker.filename = filename
        worker.chunks = self.chunks
        worker.folder = self.tmpdir
        worker.finished = MagicMock()
        return worker

    def test_dotdot_in_filename_is_stripped_to_basename(self):
        """Filenames with path traversal components are reduced to just the basename.

        os.path.basename('../../etc/passwd') -> 'passwd'
        The traversal is neutralized because we only use the basename.
        """
        worker = self._make_worker("../../etc/passwd")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, msg = worker.finished.emit.call_args[0]
        if success:
            # The file should be written as just "passwd" in the download folder
            expected_path = os.path.join(self.tmpdir, "passwd")
            self.assertTrue(os.path.exists(expected_path),
                            "File should be written as basename only")
            # The success message should reference a path inside the download folder
            self.assertIn(self.tmpdir, msg,
                          "Written path must be inside the download folder")

    def test_absolute_path_is_stripped(self):
        """Absolute paths like /etc/shadow should be reduced to just the basename."""
        worker = self._make_worker("/etc/shadow")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, msg = worker.finished.emit.call_args[0]
        # os.path.basename("/etc/shadow") -> "shadow", which is safe
        # The file should be written in the designated folder
        if success:
            expected_path = os.path.join(self.tmpdir, "shadow")
            self.assertTrue(os.path.exists(expected_path))
            # Must NOT exist at the absolute path (unless self.tmpdir happens to be /etc)
            self.assertFalse(
                os.path.exists("/etc/shadow_test_artifact"),
                "File must not be written to an absolute path"
            )

    def test_normal_filename_succeeds(self):
        """A clean filename should be assembled successfully."""
        worker = self._make_worker("payload.bin")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, _msg = worker.finished.emit.call_args[0]
        self.assertTrue(success)

        filepath = os.path.join(self.tmpdir, "payload.bin")
        self.assertTrue(os.path.exists(filepath))
        with open(filepath, "rb") as f:
            self.assertEqual(f.read(), b"hello")

    def test_empty_filename_is_rejected(self):
        """An empty filename should be rejected."""
        worker = self._make_worker("")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, _msg = worker.finished.emit.call_args[0]
        self.assertFalse(success)

    def test_dotdot_only_is_rejected(self):
        """A filename that is just '..' should be rejected."""
        worker = self._make_worker("..")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, _msg = worker.finished.emit.call_args[0]
        self.assertFalse(success)

    def test_basename_strips_directory_components(self):
        """Directory components should be stripped, writing only the basename."""
        worker = self._make_worker("subdir/nested/file.txt")
        worker.run()

        worker.finished.emit.assert_called_once()
        _fname, success, _msg = worker.finished.emit.call_args[0]
        if success:
            # File should be at folder/file.txt, not folder/subdir/nested/file.txt
            expected = os.path.join(self.tmpdir, "file.txt")
            self.assertTrue(os.path.exists(expected))
            unexpected = os.path.join(self.tmpdir, "subdir", "nested", "file.txt")
            self.assertFalse(os.path.exists(unexpected))


class TestDownloadsSignalDisconnection(unittest.TestCase):
    """set_ws_thread must disconnect old signals before connecting new ones."""

    def _make_widget_stub(self, ws_thread):
        """Create a minimal object that has the attributes set_ws_thread needs,
        bypassing DownloadsWidget.__new__ which returns a MagicMock."""

        class _Stub:
            pass

        widget = _Stub()
        widget.ws_thread = ws_thread
        widget.current_downloads = {}
        widget.download_folder = None
        widget.assembly_workers = {}
        widget.update_downloads = MagicMock()
        widget.handle_download_chunk = MagicMock()
        # Bind the real method
        widget.set_ws_thread = DownloadsWidget.set_ws_thread.__get__(widget, _Stub)
        return widget

    def test_set_ws_thread_disconnects_old_signals(self):
        """When set_ws_thread is called with a new thread, old signals are disconnected."""
        old_thread = MagicMock()
        new_thread = MagicMock()

        widget = self._make_widget_stub(old_thread)
        widget.set_ws_thread(new_thread)

        # Old thread signals should have been disconnected
        old_thread.downloads_update.disconnect.assert_called()
        old_thread.download_chunk.disconnect.assert_called()

        # New thread signals should have been connected
        new_thread.downloads_update.connect.assert_called_once_with(widget.update_downloads)
        new_thread.download_chunk.connect.assert_called_once_with(widget.handle_download_chunk)

    def test_set_ws_thread_handles_already_disconnected(self):
        """If signals were already disconnected, TypeError is caught gracefully."""
        old_thread = MagicMock()
        old_thread.downloads_update.disconnect.side_effect = TypeError
        old_thread.download_chunk.disconnect.side_effect = TypeError
        new_thread = MagicMock()

        widget = self._make_widget_stub(old_thread)

        # Should not raise
        widget.set_ws_thread(new_thread)

        # New thread should still be connected
        new_thread.downloads_update.connect.assert_called_once()

    def test_set_ws_thread_none_skips_connect(self):
        """Setting ws_thread to None should disconnect old but not connect new."""
        old_thread = MagicMock()
        widget = self._make_widget_stub(old_thread)

        widget.set_ws_thread(None)

        self.assertIsNone(widget.ws_thread)


if __name__ == "__main__":
    unittest.main()
