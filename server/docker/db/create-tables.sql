CREATE TABLE IF NOT EXISTS user_sessions (
    sesion_id UUID PRIMARY KEY,
    username VARCHAR NOT NULL,
    login_time TIMESTAMP NOT NULL,
    logout_time TIMESTAMP
);

CREATE TABLE IF NOT EXISTS commands (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    guid VARCHAR(255) NOT NULL,
    command TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS command_outputs (
    id SERIAL PRIMARY KEY,
    command_id INTEGER REFERENCES commands(id) ON DELETE CASCADE,
    output TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS agent_aliases (
    guid TEXT PRIMARY KEY,
    alias TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS listeners (
    id UUID PRIMARY KEY,
    name VARCHAR NOT NULL,
    protocol VARCHAR NOT NULL,
    port VARCHAR NOT NULL,
    ip VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS inits (
    id UUID PRIMARY KEY,
    clientID UUID NOT NULL,
    type VARCHAR NOT NULL,
    secret VARCHAR NOT NULL,
    os VARCHAR NOT NULL,
    arch VARCHAR NOT NULL,
    RSAkey VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS connections (
    newclientID UUID PRIMARY KEY,
    clientID VARCHAR NOT NULL,
    protocol VARCHAR NOT NULL,
    secret1 VARCHAR NOT NULL,
    secret2 VARCHAR NOT NULL,
    extIP VARCHAR NULL,
    intIP VARCHAR NULL,
    username VARCHAR NULL,
    hostname VARCHAR NULL,
    note TEXT,
    process VARCHAR NULL,
    pid VARCHAR NULL,
    arch VARCHAR NOT NULL,
    lastSEEN TIMESTAMP NOT NULL,
    os VARCHAR NULL,
    proto VARCHAR NOT NULL,
    deleted_at TIMESTAMP NULL DEFAULT NULL,
    alias VARCHAR DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS link_routes (
    id UUID PRIMARY KEY,
    source_guid UUID NOT NULL,
    destination_guid UUID NOT NULL,
    next_hop_guid UUID NOT NULL,
    hop_count INTEGER NOT NULL,
    route_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active',
    FOREIGN KEY (source_guid) REFERENCES connections(GUID),
    FOREIGN KEY (destination_guid) REFERENCES links(GUID),
    FOREIGN KEY (next_hop_guid) REFERENCES links(GUID)
);