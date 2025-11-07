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
                        alias TEXT NULL
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
                        ip TEXT NOT NULL
                    );
                """)
                
                # Debug: Print current table contents after initialization
                print("\nDEBUG: Checking database tables after initialization:")
                for table in ['connections', 'commands', 'command_outputs', 'listeners']:
                    cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    print(f"Table {table}: {count} rows")
                    if table == 'connections':
                        print("\nConnections table contents:")
                        cursor = conn.execute("SELECT * FROM connections")
                        for row in cursor.fetchall():
                            print(row)


    def store_state(self, state_data):
            """Store state data with thread safety."""
            with self._db_lock:
                with self._get_connection() as conn:
                    # Start transaction
                    conn.execute("BEGIN TRANSACTION")
                    try:
                        # Clear existing data
                        conn.executescript("""
                            DELETE FROM connections;
                            DELETE FROM commands;
                            DELETE FROM command_outputs;
                            DELETE FROM listeners;
                        """)

                        # Store listeners
                        if state_data.get("listeners"):
                            print("Storing listeners in database")
                            conn.executemany(
                                "INSERT INTO listeners (id, name, protocol, port, ip) VALUES (?,?,?,?,?)",
                                [(l["id"], l["name"], l["protocol"], l["port"], l["ip"]) 
                                for l in state_data["listeners"] if l is not None]
                            )
                            print(f"Stored {len(state_data['listeners'])} listeners")

                        # Store connections
                        if state_data.get("connections"):
                            print("Storing connections in database")
                            conn.executemany(
                                """INSERT INTO connections (
                                    newclient_id, client_id, protocol, extIP, intIP, 
                                    username, hostname, note, process, pid, 
                                    arch, lastSEEN, os, proto, deleted_at, alias
                                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                                    c.get("alias") 
                                ) for c in state_data["connections"] if c is not None]
                            )
                            print(f"Stored {len(state_data['connections'])} connections")

                        # Store commands
                        if state_data.get("commands"):
                            print("Storing commands in database")
                            conn.executemany(
                                """INSERT INTO commands (
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
                            print(f"Stored {len(state_data['commands'])} commands")

                        # Store command outputs
                        if state_data.get("command_outputs"):
                            print("Storing command outputs in database")
                            conn.executemany(
                                """INSERT INTO command_outputs (
                                    id, command_id, output, timestamp
                                ) VALUES (?,?,?,?)""",
                                [(
                                    output["id"],
                                    output["command_id"],
                                    output["output"],
                                    output["timestamp"]
                                ) for output in state_data["command_outputs"] if output is not None]
                            )
                            print(f"Stored {len(state_data['command_outputs'])} command outputs")

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