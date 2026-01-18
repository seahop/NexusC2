import sqlite3
import os
import threading

class StateDatabase:
    _db_lock = threading.Lock()  # Class-level lock for database operations
    _connections = threading.local()  # Thread-local storage for connections

    def __init__(self, db_path="state.db"):
        self.db_path = db_path
        self.init_db()

    def _get_connection(self):
        """Get a thread-local database connection."""
        if not hasattr(self._connections, 'conn'):
            self._connections.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        return self._connections.conn

    def _close_connections(self):
        """Close thread-local database connections."""
        if hasattr(self._connections, 'conn'):
            self._connections.conn.close()
            delattr(self._connections, 'conn')

    def _run_migrations(self, conn):
        """Run schema migrations to add missing columns to existing tables."""
        # Get existing columns for listeners table
        cursor = conn.execute("PRAGMA table_info(listeners)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        # Migration: Add pipe_name column to listeners if missing
        if 'pipe_name' not in existing_columns:
            print("StateDatabase: Migrating listeners table - adding pipe_name column")
            conn.execute("ALTER TABLE listeners ADD COLUMN pipe_name TEXT DEFAULT ''")
            print("StateDatabase: Migration complete - pipe_name column added")

        # Migration: Add profile columns to listeners if missing
        if 'get_profile' not in existing_columns:
            print("StateDatabase: Migrating listeners table - adding get_profile column")
            conn.execute("ALTER TABLE listeners ADD COLUMN get_profile TEXT DEFAULT 'default-get'")
            print("StateDatabase: Migration complete - get_profile column added")

        if 'post_profile' not in existing_columns:
            print("StateDatabase: Migrating listeners table - adding post_profile column")
            conn.execute("ALTER TABLE listeners ADD COLUMN post_profile TEXT DEFAULT 'default-post'")
            print("StateDatabase: Migration complete - post_profile column added")

        if 'server_response_profile' not in existing_columns:
            print("StateDatabase: Migrating listeners table - adding server_response_profile column")
            conn.execute("ALTER TABLE listeners ADD COLUMN server_response_profile TEXT DEFAULT 'default-response'")
            print("StateDatabase: Migration complete - server_response_profile column added")

        # Get existing columns for connections table
        cursor = conn.execute("PRAGMA table_info(connections)")
        conn_columns = {row[1] for row in cursor.fetchall()}

        # Migration: Add parent_client_id column to connections if missing (for linked agents)
        if 'parent_client_id' not in conn_columns:
            print("StateDatabase: Migrating connections table - adding parent_client_id column")
            conn.execute("ALTER TABLE connections ADD COLUMN parent_client_id TEXT NULL")
            print("StateDatabase: Migration complete - parent_client_id column added")

        # Migration: Add link_type column to connections if missing (for linked agents)
        if 'link_type' not in conn_columns:
            print("StateDatabase: Migrating connections table - adding link_type column")
            conn.execute("ALTER TABLE connections ADD COLUMN link_type TEXT NULL")
            print("StateDatabase: Migration complete - link_type column added")

    def init_db(self):
        """Initialize the database schema with thread safety."""
        with self._db_lock:  # Ensure exclusive access during initialization
            with self._get_connection() as conn:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS connections (
                        newclient_id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        extIP TEXT,
                        intIP TEXT,
                        username TEXT,
                        hostname TEXT,
                        note TEXT,
                        process TEXT,
                        pid TEXT,
                        arch TEXT NOT NULL,
                        lastSEEN TIMESTAMP NOT NULL,
                        os TEXT,
                        proto TEXT NOT NULL,
                        deleted_at TIMESTAMP NULL DEFAULT NULL,
                        alias TEXT NULL,
                        parent_client_id TEXT NULL,
                        link_type TEXT NULL
                    );
                    CREATE TABLE IF NOT EXISTS commands (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        guid TEXT NOT NULL,
                        command TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS command_outputs (
                        id INTEGER PRIMARY KEY,
                        command_id INTEGER REFERENCES commands(id),
                        output TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE IF NOT EXISTS listeners (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        port TEXT NOT NULL,
                        ip TEXT NOT NULL,
                        pipe_name TEXT DEFAULT '',
                        get_profile TEXT DEFAULT 'default-get',
                        post_profile TEXT DEFAULT 'default-post',
                        server_response_profile TEXT DEFAULT 'default-response'
                    );
                    CREATE TABLE IF NOT EXISTS agent_tags (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        agent_guid TEXT NOT NULL,
                        tag_name TEXT NOT NULL,
                        tag_color TEXT DEFAULT '#4A90E2',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (agent_guid) REFERENCES connections(newclient_id) ON DELETE CASCADE,
                        UNIQUE(agent_guid, tag_name)
                    );

                    -- Performance indexes
                    CREATE INDEX IF NOT EXISTS idx_connections_newclient_id ON connections(newclient_id);
                    CREATE INDEX IF NOT EXISTS idx_connections_deleted_at ON connections(deleted_at);
                    CREATE INDEX IF NOT EXISTS idx_connections_lastSEEN ON connections(lastSEEN DESC);
                    CREATE INDEX IF NOT EXISTS idx_connections_deleted_lastseen ON connections(deleted_at, lastSEEN DESC);
                    CREATE INDEX IF NOT EXISTS idx_commands_guid ON commands(guid);
                    CREATE INDEX IF NOT EXISTS idx_commands_timestamp ON commands(timestamp DESC);
                    CREATE INDEX IF NOT EXISTS idx_command_outputs_command_id ON command_outputs(command_id);
                    CREATE INDEX IF NOT EXISTS idx_command_outputs_timestamp ON command_outputs(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_agent_tags_guid ON agent_tags(agent_guid);
                    CREATE INDEX IF NOT EXISTS idx_agent_tags_name ON agent_tags(tag_name);

                    -- CNA scripts persistence table
                    CREATE TABLE IF NOT EXISTS cna_scripts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        script_path TEXT NOT NULL UNIQUE,
                        enabled INTEGER DEFAULT 1,
                        load_order INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_error TEXT NULL,
                        last_error_at TIMESTAMP NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_cna_scripts_path ON cna_scripts(script_path);
                    CREATE INDEX IF NOT EXISTS idx_cna_scripts_enabled ON cna_scripts(enabled);

                    -- Available malleable profiles (from server config)
                    CREATE TABLE IF NOT EXISTS available_profiles (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        profile_type TEXT NOT NULL,
                        profile_name TEXT NOT NULL,
                        UNIQUE(profile_type, profile_name)
                    );
                    CREATE INDEX IF NOT EXISTS idx_available_profiles_type ON available_profiles(profile_type);
                """)

                # Schema migrations - add missing columns to existing tables
                self._run_migrations(conn)

                # Debug: Print current table contents after initialization
                print("\nDEBUG: Checking database tables after initialization:")
                for table in ['connections', 'commands', 'command_outputs', 'listeners', 'agent_tags']:
                    cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    print(f"Table {table}: {count} rows")
                    if table == 'connections':
                        print("\nConnections table contents:")
                        cursor = conn.execute("SELECT * FROM connections")
                        for row in cursor.fetchall():
                            print(row)


    def store_state(self, state_data, is_initial_state=False):
            """Store state data with thread safety using UPSERT for efficiency.

            Args:
                state_data: Dictionary containing state data (listeners, connections, commands, etc.)
                is_initial_state: If True, clears existing data before storing (for server reconnect/wipe)
            """
            with self._db_lock:
                with self._get_connection() as conn:
                    # Start transaction
                    conn.execute("BEGIN TRANSACTION")
                    try:
                        # If this is initial state (e.g., after server wipe), clear existing cached data
                        if is_initial_state:
                            print("StateDatabase: Clearing stale cache data (initial_state received)")
                            conn.execute("DELETE FROM listeners")
                            conn.execute("DELETE FROM connections")
                            conn.execute("DELETE FROM commands")
                            conn.execute("DELETE FROM command_outputs")
                            print("StateDatabase: Cleared listeners, connections, commands, and command_outputs")

                        # Store listeners using UPSERT
                        if state_data.get("listeners"):
                            print("Upserting listeners in database")
                            conn.executemany(
                                """INSERT OR REPLACE INTO listeners
                                   (id, name, protocol, port, ip, pipe_name, get_profile, post_profile, server_response_profile)
                                   VALUES (?,?,?,?,?,?,?,?,?)""",
                                [(l["id"], l["name"], l["protocol"], l["port"], l["ip"],
                                  l.get("pipe_name", ""),
                                  l.get("get_profile", "default-get"),
                                  l.get("post_profile", "default-post"),
                                  l.get("server_response_profile", "default-response"))
                                for l in state_data["listeners"] if l is not None]
                            )
                            print(f"Upserted {len(state_data['listeners'])} listeners")
                        elif is_initial_state:
                            # Server sent empty listeners list - already cleared above
                            print("StateDatabase: No listeners in initial state (cache cleared)")

                        # Store connections using UPSERT
                        if state_data.get("connections"):
                            print("Upserting connections in database")
                            conn.executemany(
                                """INSERT OR REPLACE INTO connections (
                                    newclient_id, client_id, protocol, extIP, intIP,
                                    username, hostname, note, process, pid,
                                    arch, lastSEEN, os, proto, deleted_at, alias,
                                    parent_client_id, link_type
                                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                [(
                                    c["newclient_id"],
                                    c["client_id"],
                                    c["protocol"],
                                    c["ext_ip"],
                                    c["int_ip"],
                                    c["username"],
                                    c["hostname"],
                                    c.get("note", ""),
                                    c["process"],
                                    c["pid"],
                                    c["arch"],
                                    c["last_seen"],
                                    c["os"],
                                    c["proto"],
                                    c.get("deleted_at", {}).get("Time") if isinstance(c.get("deleted_at"), dict) else None,
                                    c.get("alias"),
                                    c.get("parent_client_id"),  # For linked agents
                                    c.get("link_type"),         # Link type (e.g., "smb")
                                ) for c in state_data["connections"] if c is not None]
                            )
                            print(f"Upserted {len(state_data['connections'])} connections")
                        elif is_initial_state:
                            # Server sent empty connections list - already cleared above
                            print("StateDatabase: No connections in initial state (cache cleared)")

                        # Store commands using UPSERT
                        if state_data.get("commands"):
                            print("Upserting commands in database")
                            conn.executemany(
                                """INSERT OR REPLACE INTO commands (
                                    id, username, guid, command, timestamp
                                ) VALUES (?,?,?,?,?)""",
                                [(
                                    cmd["id"],
                                    cmd["username"],
                                    cmd["guid"],
                                    cmd["command"],
                                    cmd["timestamp"]
                                ) for cmd in state_data["commands"] if cmd is not None]
                            )
                            print(f"Upserted {len(state_data['commands'])} commands")

                        # Store command outputs using UPSERT
                        if state_data.get("command_outputs"):
                            print("Upserting command outputs in database")
                            conn.executemany(
                                """INSERT OR REPLACE INTO command_outputs (
                                    id, command_id, output, timestamp
                                ) VALUES (?,?,?,?)""",
                                [(
                                    output["id"],
                                    output["command_id"],
                                    output["output"],
                                    output["timestamp"]
                                ) for output in state_data["command_outputs"] if output is not None]
                            )
                            print(f"Upserted {len(state_data['command_outputs'])} command outputs")

                        # Store agent tags using UPSERT
                        if state_data.get("agent_tags"):
                            print("Upserting agent tags in database")
                            # First clear existing tags if initial state
                            if is_initial_state:
                                conn.execute("DELETE FROM agent_tags")

                            # agent_tags is a dict: {agent_guid: [{"name": "tag", "color": "#fff"}, ...]}
                            tag_rows = []
                            for agent_guid, tags in state_data["agent_tags"].items():
                                for tag in tags:
                                    tag_rows.append((
                                        agent_guid,
                                        tag["name"],
                                        tag.get("color", "#4A90E2")
                                    ))

                            if tag_rows:
                                conn.executemany(
                                    """INSERT OR REPLACE INTO agent_tags (agent_guid, tag_name, tag_color)
                                       VALUES (?,?,?)""",
                                    tag_rows
                                )
                                print(f"Upserted {len(tag_rows)} agent tags")
                        elif is_initial_state:
                            # Server sent no tags - clear local tags
                            conn.execute("DELETE FROM agent_tags")
                            print("StateDatabase: Cleared agent tags (no tags in initial state)")

                        # Store available profiles if present
                        if state_data.get("available_profiles"):
                            print("Storing available profiles in database")
                            # Clear existing profiles first
                            conn.execute("DELETE FROM available_profiles")

                            profiles = state_data["available_profiles"]
                            profile_rows = []

                            # Store GET profiles
                            for name in profiles.get("get", []):
                                profile_rows.append(("get", name))

                            # Store POST profiles
                            for name in profiles.get("post", []):
                                profile_rows.append(("post", name))

                            # Store Server Response profiles
                            for name in profiles.get("server_response", []):
                                profile_rows.append(("server_response", name))

                            if profile_rows:
                                conn.executemany(
                                    """INSERT OR REPLACE INTO available_profiles (profile_type, profile_name)
                                       VALUES (?,?)""",
                                    profile_rows
                                )
                                print(f"Stored {len(profile_rows)} available profiles")
                        elif is_initial_state:
                            # Clear profiles if not provided in initial state
                            conn.execute("DELETE FROM available_profiles")
                            print("StateDatabase: Cleared available profiles (none in initial state)")

                        # Commit transaction
                        conn.commit()
                        return True

                    except Exception as e:
                        print(f"Error storing state: {e}")
                        import traceback
                        traceback.print_exc()
                        conn.rollback()
                        return False
                
    def fetch_commands_and_outputs(self):
        """Fetch commands and their outputs from the database."""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Fetch commands without joining to connections
                cursor.execute("""
                    SELECT 
                        id, 
                        username, 
                        guid, 
                        command, 
                        timestamp
                    FROM commands
                    ORDER BY timestamp ASC
                """)
                commands = cursor.fetchall()
                print(f"Database: Fetched {len(commands)} commands")

                # Fetch outputs without requiring connections
                cursor.execute("""
                    SELECT 
                        id, 
                        command_id, 
                        output, 
                        timestamp
                    FROM command_outputs
                    ORDER BY timestamp ASC
                """)
                outputs = cursor.fetchall()
                print(f"Database: Fetched {len(outputs)} command outputs")

                return {"commands": commands, "outputs": outputs or []}
            
    def recreate_database(self):
        """Delete and recreate the database with thread safety."""
        with self._db_lock:  # Ensure exclusive access during recreation
            try:
                # Close any existing connections
                self._close_connections()
                
                # Remove existing database
                if os.path.exists(self.db_path):
                    os.remove(self.db_path)
                    print(f"StateDatabase: Deleted existing database file at {self.db_path}")
                
                # Recreate database
                self.init_db()
                print(f"StateDatabase: Recreated database file and initialized schema.")

                # Set permissions
                if os.path.exists(self.db_path):
                    os.chmod(self.db_path, 0o666)
                    print(f"StateDatabase: Set writable permissions for {self.db_path}")
                
                return True
            except Exception as e:
                print(f"StateDatabase: Failed to recreate database: {e}")
                return False

    def __del__(self):
        """Cleanup when the object is deleted."""
        self._close_connections()

    def get_agent_tags(self, agent_guid):
        """Get all tags for a specific agent"""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT tag_name, tag_color
                    FROM agent_tags
                    WHERE agent_guid = ?
                    ORDER BY tag_name ASC
                """, (agent_guid,))
                rows = cursor.fetchall()
                return [{"name": row[0], "color": row[1]} for row in rows]

    def get_all_agent_tags(self):
        """Get all agent tags as a dictionary {agent_guid: [tags]}"""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT agent_guid, tag_name, tag_color
                    FROM agent_tags
                    ORDER BY agent_guid, tag_name ASC
                """)
                rows = cursor.fetchall()

                # Build dictionary
                tags_dict = {}
                for row in rows:
                    agent_guid = row[0]
                    tag = {"name": row[1], "color": row[2]}
                    if agent_guid not in tags_dict:
                        tags_dict[agent_guid] = []
                    tags_dict[agent_guid].append(tag)

                return tags_dict

    def get_available_profiles(self):
        """Get available malleable profiles as a dictionary with lists by type"""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT profile_type, profile_name
                    FROM available_profiles
                    ORDER BY profile_type, profile_name ASC
                """)
                rows = cursor.fetchall()

                # Build dictionary with lists
                profiles = {
                    "get": [],
                    "post": [],
                    "server_response": []
                }

                for row in rows:
                    profile_type = row[0]
                    profile_name = row[1]
                    if profile_type in profiles:
                        profiles[profile_type].append(profile_name)

                # Ensure we have at least default profiles if empty
                if not profiles["get"]:
                    profiles["get"] = ["default-get"]
                if not profiles["post"]:
                    profiles["post"] = ["default-post"]
                if not profiles["server_response"]:
                    profiles["server_response"] = ["default-response"]

                return profiles

    def update_profiles(self, profile_data):
        """Update available profiles from server broadcast/response

        Args:
            profile_data: dict with keys 'get_profiles', 'post_profiles', 'server_response_profiles'
        """
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    # Clear existing profiles
                    conn.execute("DELETE FROM available_profiles")

                    profile_rows = []

                    # Handle different key formats from server
                    get_profiles = profile_data.get("get_profiles", profile_data.get("get", []))
                    post_profiles = profile_data.get("post_profiles", profile_data.get("post", []))
                    response_profiles = profile_data.get("server_response_profiles",
                                                         profile_data.get("server_response", []))

                    # Store GET profiles
                    for name in get_profiles:
                        profile_rows.append(("get", name))

                    # Store POST profiles
                    for name in post_profiles:
                        profile_rows.append(("post", name))

                    # Store Server Response profiles
                    for name in response_profiles:
                        profile_rows.append(("server_response", name))

                    if profile_rows:
                        conn.executemany(
                            """INSERT OR REPLACE INTO available_profiles (profile_type, profile_name)
                               VALUES (?,?)""",
                            profile_rows
                        )

                    conn.commit()
                    print(f"Updated profiles: {len(get_profiles)} GET, {len(post_profiles)} POST, {len(response_profiles)} Response")
                    return True
                except Exception as e:
                    print(f"Error updating profiles: {e}")
                    conn.rollback()
                    return False

    def update_agent_tags(self, agent_guid, tags):
        """Update all tags for a specific agent (replaces existing)"""
        with self._db_lock:
            with self._get_connection() as conn:
                conn.execute("BEGIN TRANSACTION")
                try:
                    # Clear existing tags for this agent
                    conn.execute("DELETE FROM agent_tags WHERE agent_guid = ?", (agent_guid,))

                    # Insert new tags
                    if tags:
                        conn.executemany(
                            """INSERT INTO agent_tags (agent_guid, tag_name, tag_color)
                               VALUES (?,?,?)""",
                            [(agent_guid, tag["name"], tag.get("color", "#4A90E2")) for tag in tags]
                        )

                    conn.commit()
                    print(f"Updated tags for agent {agent_guid}: {len(tags)} tags")
                    return True
                except Exception as e:
                    print(f"Error updating agent tags: {e}")
                    conn.rollback()
                    return False

    def verify_database_state(self):
        """Verify and print current database state"""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check listeners
                cursor.execute("SELECT * FROM listeners")
                listeners = cursor.fetchall()
                print("\nCurrent listeners in database:")
                for listener in listeners:
                    print(f"- ID: {listener[0]}")
                    print(f"  Name: {listener[1]}")
                    print(f"  Protocol: {listener[2]}")
                    print(f"  Port: {listener[3]}")
                    print(f"  IP: {listener[4]}")
                    if len(listener) > 5 and listener[5]:
                        print(f"  Pipe Name: {listener[5]}")
                    if len(listener) > 6:
                        print(f"  GET Profile: {listener[6]}")
                    if len(listener) > 7:
                        print(f"  POST Profile: {listener[7]}")
                    if len(listener) > 8:
                        print(f"  Response Profile: {listener[8]}")
                
                # Get counts
                cursor.execute("SELECT COUNT(*) FROM listeners")
                listener_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM connections")
                connection_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM commands")
                command_count = cursor.fetchone()[0]
                
                print("\nDatabase state:")
                print(f"- Listeners: {listener_count}")
                print(f"- Connections: {connection_count}")
                print(f"- Commands: {command_count}")

    # CNA Script Persistence Methods
    def add_cna_script(self, script_path: str) -> bool:
        """Add a CNA script to the persistence store"""
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    # Get current max load_order
                    cursor = conn.cursor()
                    cursor.execute("SELECT MAX(load_order) FROM cna_scripts")
                    result = cursor.fetchone()
                    next_order = (result[0] or 0) + 1

                    conn.execute(
                        """INSERT OR REPLACE INTO cna_scripts (script_path, enabled, load_order)
                           VALUES (?, 1, ?)""",
                        (script_path, next_order)
                    )
                    conn.commit()
                    print(f"StateDatabase: Added CNA script: {script_path}")
                    return True
                except Exception as e:
                    print(f"StateDatabase: Error adding CNA script: {e}")
                    return False

    def remove_cna_script(self, script_path: str) -> bool:
        """Remove a CNA script from the persistence store"""
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    conn.execute("DELETE FROM cna_scripts WHERE script_path = ?", (script_path,))
                    conn.commit()
                    print(f"StateDatabase: Removed CNA script: {script_path}")
                    return True
                except Exception as e:
                    print(f"StateDatabase: Error removing CNA script: {e}")
                    return False

    def get_cna_scripts(self, enabled_only: bool = True) -> list:
        """Get all persisted CNA scripts"""
        with self._db_lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if enabled_only:
                    cursor.execute(
                        """SELECT script_path, enabled, load_order, last_error, last_error_at
                           FROM cna_scripts
                           WHERE enabled = 1
                           ORDER BY load_order ASC"""
                    )
                else:
                    cursor.execute(
                        """SELECT script_path, enabled, load_order, last_error, last_error_at
                           FROM cna_scripts
                           ORDER BY load_order ASC"""
                    )
                rows = cursor.fetchall()
                return [
                    {
                        "script_path": row[0],
                        "enabled": bool(row[1]),
                        "load_order": row[2],
                        "last_error": row[3],
                        "last_error_at": row[4]
                    }
                    for row in rows
                ]

    def update_cna_script_error(self, script_path: str, error: str) -> bool:
        """Update the last error for a CNA script (for startup load failures)"""
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    conn.execute(
                        """UPDATE cna_scripts
                           SET last_error = ?, last_error_at = CURRENT_TIMESTAMP
                           WHERE script_path = ?""",
                        (error, script_path)
                    )
                    conn.commit()
                    return True
                except Exception as e:
                    print(f"StateDatabase: Error updating CNA script error: {e}")
                    return False

    def clear_cna_script_error(self, script_path: str) -> bool:
        """Clear the last error for a CNA script (on successful load)"""
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    conn.execute(
                        """UPDATE cna_scripts
                           SET last_error = NULL, last_error_at = NULL
                           WHERE script_path = ?""",
                        (script_path,)
                    )
                    conn.commit()
                    return True
                except Exception as e:
                    print(f"StateDatabase: Error clearing CNA script error: {e}")
                    return False

    def set_cna_script_enabled(self, script_path: str, enabled: bool) -> bool:
        """Enable or disable a CNA script"""
        with self._db_lock:
            with self._get_connection() as conn:
                try:
                    conn.execute(
                        "UPDATE cna_scripts SET enabled = ? WHERE script_path = ?",
                        (1 if enabled else 0, script_path)
                    )
                    conn.commit()
                    return True
                except Exception as e:
                    print(f"StateDatabase: Error updating CNA script enabled state: {e}")
                    return False