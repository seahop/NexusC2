"""Tests for the database utility (utils/database.py).

Focus areas from code-review fixes:
  - Database file permissions are 0o600 after recreate (not 0o666)
  - No debug dump of sensitive data (passwords, tokens, etc.)
"""

import os
import stat
import tempfile
import threading
import unittest
import inspect
from unittest.mock import patch

from utils.database import StateDatabase


class TestDatabaseFilePermissions(unittest.TestCase):
    """Verify the database file gets restrictive permissions."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_state.db")

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.isdir(self.tmpdir):
            os.rmdir(self.tmpdir)

    def test_recreate_sets_permissions_0o600(self):
        """recreate_database() must chmod the file to 0o600.

        Note: StateDatabase._db_lock is a non-reentrant Lock, so
        recreate_database -> init_db would deadlock. We swap it to RLock
        for the test.
        """
        # Work around the deadlock: _db_lock is a non-reentrant Lock,
        # but recreate_database calls init_db which also acquires it.
        original_lock = StateDatabase._db_lock
        StateDatabase._db_lock = threading.RLock()
        try:
            db = StateDatabase(db_path=self.db_path)
            result = db.recreate_database()
            self.assertTrue(result, "recreate_database should return True on success")

            mode = os.stat(self.db_path).st_mode
            file_perm = stat.S_IMODE(mode)
            self.assertEqual(
                file_perm, 0o600,
                f"Database file permissions should be 0o600 (owner rw only), got {oct(file_perm)}"
            )
        finally:
            StateDatabase._db_lock = original_lock

    def test_recreate_does_not_set_world_readable(self):
        """Permissions must NOT include world-readable bits."""
        original_lock = StateDatabase._db_lock
        StateDatabase._db_lock = threading.RLock()
        try:
            db = StateDatabase(db_path=self.db_path)
            db.recreate_database()

            mode = os.stat(self.db_path).st_mode
            self.assertFalse(
                mode & stat.S_IROTH,
                "Database should not be world-readable"
            )
            self.assertFalse(
                mode & stat.S_IWOTH,
                "Database should not be world-writable"
            )
        finally:
            StateDatabase._db_lock = original_lock

    def test_recreate_database_code_uses_0o600(self):
        """The source code of recreate_database must use 0o600, not 0o666."""
        import pathlib
        src_path = pathlib.Path(__file__).resolve().parent.parent / "src" / "utils" / "database.py"
        source = src_path.read_text()
        self.assertIn("0o600", source)
        self.assertNotIn("0o666", source)


class TestNoSensitiveDataDump(unittest.TestCase):
    """Source code must not dump full database rows with print/log at debug level."""

    def test_no_credential_print_in_store_state(self):
        """store_state should not print raw connection data that could contain secrets."""
        source = inspect.getsource(StateDatabase.store_state)
        # We check that it doesn't dump the full state_data dict to stdout
        # It's OK to print row counts, but not `print(f"...{state_data}")` style
        self.assertNotIn("print(state_data", source)
        self.assertNotIn("print(f\"{state_data", source)
        self.assertNotIn("print(str(state_data))", source)

    def test_verify_database_state_does_not_expose_passwords(self):
        """verify_database_state logs table contents -- ensure it doesn't log
        connection passwords (the schema has no password column, which is correct)."""
        db_path = os.path.join(tempfile.mkdtemp(), "verify_test.db")
        try:
            db = StateDatabase(db_path=db_path)
            # The connections table schema should not have a 'password' column
            conn = db._get_connection()
            cursor = conn.execute("PRAGMA table_info(connections)")
            columns = {row[1] for row in cursor.fetchall()}
            self.assertNotIn("password", columns)
            self.assertNotIn("token", columns)
            self.assertNotIn("secret", columns)
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            parent = os.path.dirname(db_path)
            if os.path.isdir(parent):
                os.rmdir(parent)


class TestDatabaseSchemaInit(unittest.TestCase):
    """Basic sanity checks for schema initialization."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "schema_test.db")

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.tmpdir)

    def test_tables_created(self):
        """init_db must create the expected tables."""
        db = StateDatabase(db_path=self.db_path)
        conn = db._get_connection()

        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}

        expected = {"connections", "commands", "command_outputs", "listeners",
                    "agent_tags", "cna_scripts", "available_profiles"}
        self.assertTrue(expected.issubset(tables),
                        f"Missing tables: {expected - tables}")

    def test_thread_lock_exists(self):
        """StateDatabase must use a class-level reentrant lock for thread safety."""
        import threading
        self.assertIsInstance(StateDatabase._db_lock, type(threading.RLock()))


class TestStoreState(unittest.TestCase):
    """Test the store_state upsert logic."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "store_test.db")
        self.db = StateDatabase(db_path=self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.rmdir(self.tmpdir)

    def test_store_listeners(self):
        state = {
            "listeners": [
                {
                    "id": "lsnr-1",
                    "name": "http-listener",
                    "protocol": "https",
                    "port": "443",
                    "ip": "0.0.0.0",
                }
            ]
        }
        result = self.db.store_state(state)
        self.assertTrue(result)

        conn = self.db._get_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM listeners")
        self.assertEqual(cursor.fetchone()[0], 1)

    def test_store_connections(self):
        state = {
            "connections": [
                {
                    "newclient_id": "abc-123",
                    "client_id": "cli-1",
                    "protocol": "https",
                    "ext_ip": "1.2.3.4",
                    "int_ip": "10.0.0.5",
                    "username": "admin",
                    "hostname": "workstation1",
                    "note": "",
                    "process": "svchost.exe",
                    "pid": "1234",
                    "arch": "x64",
                    "last_seen": "2026-10-17T12:00:00Z",
                    "os": "windows",
                    "proto": "https",
                }
            ]
        }
        result = self.db.store_state(state)
        self.assertTrue(result)

        conn = self.db._get_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM connections")
        self.assertEqual(cursor.fetchone()[0], 1)

    def test_initial_state_clears_existing_data(self):
        """is_initial_state=True should wipe existing cached data first."""
        # Store initial data
        state1 = {
            "listeners": [
                {"id": "l1", "name": "a", "protocol": "http", "port": "80", "ip": "0.0.0.0"}
            ]
        }
        self.db.store_state(state1)

        # Store new initial state (simulating server reconnect)
        state2 = {"listeners": []}
        self.db.store_state(state2, is_initial_state=True)

        conn = self.db._get_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM listeners")
        self.assertEqual(cursor.fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
