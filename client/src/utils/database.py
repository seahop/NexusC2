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
                        pipe_name TEXT DEFAULT ''
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
                            # Don't clear commands/command_outputs - preserve terminal history
                            print("StateDatabase: Cleared listeners and connections")

                        # Store listeners using UPSERT
                        if state_data.get("listeners"):
                            print("Upserting listeners in database")
                            conn.executemany(
                                """INSERT OR REPLACE INTO listeners (id, name, protocol, port, ip, pipe_name)
                                   VALUES (?,?,?,?,?,?)""",
                                [(l["id"], l["name"], l["protocol"], l["port"], l["ip"], l.get("pipe_name", ""))
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