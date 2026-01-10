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
    ip VARCHAR NOT NULL,
    pipe_name VARCHAR DEFAULT ''
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

CREATE TABLE IF NOT EXISTS agent_tags (
    id SERIAL PRIMARY KEY,
    agent_guid UUID NOT NULL,
    tag_name VARCHAR(100) NOT NULL,
    tag_color VARCHAR(7) DEFAULT '#4A90E2',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (agent_guid) REFERENCES connections(newclientID) ON DELETE CASCADE,
    UNIQUE(agent_guid, tag_name)
);

CREATE TABLE IF NOT EXISTS link_routes (
    id UUID PRIMARY KEY,
    source_guid UUID NOT NULL,
    destination_guid UUID NOT NULL,
    next_hop_guid UUID NOT NULL,
    hop_count INTEGER NOT NULL,
    route_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP,
    status VARCHAR(50) DEFAULT 'active'
    -- Note: Foreign keys commented out - links table doesn't exist
    -- FOREIGN KEY (source_guid) REFERENCES connections(GUID),
    -- FOREIGN KEY (destination_guid) REFERENCES links(GUID),
    -- FOREIGN KEY (next_hop_guid) REFERENCES links(GUID)
);

-- =============================================================================
-- SMB LINK ROUTING TABLE
-- =============================================================================
-- Maps (edge_clientID, routing_id) -> smb_clientID for link traffic routing

CREATE TABLE IF NOT EXISTS link_routing (
    id SERIAL PRIMARY KEY,
    edge_clientID UUID NOT NULL,
    routing_id VARCHAR(16) NOT NULL,
    linked_clientID UUID NOT NULL,
    link_type VARCHAR(20) DEFAULT 'smb',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    UNIQUE(edge_clientID, routing_id)
);

-- Add parent tracking columns to connections table if they don't exist
-- These track the link hierarchy for multi-hop routing
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'connections' AND column_name = 'parent_clientid') THEN
        ALTER TABLE connections ADD COLUMN parent_clientID UUID NULL;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'connections' AND column_name = 'link_type') THEN
        ALTER TABLE connections ADD COLUMN link_type VARCHAR(20) NULL;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'connections' AND column_name = 'hop_count') THEN
        ALTER TABLE connections ADD COLUMN hop_count INTEGER DEFAULT 0;
    END IF;
END $$;

-- =============================================================================
-- REST API AUTHENTICATION TABLES
-- =============================================================================
-- Separate user management for API access (not the same as GUI users)

CREATE TABLE IF NOT EXISTS api_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES api_users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- PERFORMANCE INDEXES
-- ============================================================================

-- Connections table indexes (hot path for agent management)
CREATE INDEX IF NOT EXISTS idx_connections_lastseen
    ON connections(lastSEEN DESC);

CREATE INDEX IF NOT EXISTS idx_connections_deleted
    ON connections(deleted_at)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_connections_deleted_lastseen
    ON connections(deleted_at, lastSEEN DESC);

CREATE INDEX IF NOT EXISTS idx_connections_clientid
    ON connections(clientID);

-- Commands table indexes (audit log queries)
CREATE INDEX IF NOT EXISTS idx_commands_guid_timestamp
    ON commands(guid, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_commands_timestamp
    ON commands(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_commands_username
    ON commands(username);

-- Command outputs indexes (result retrieval)
CREATE INDEX IF NOT EXISTS idx_command_outputs_command_id
    ON command_outputs(command_id);

CREATE INDEX IF NOT EXISTS idx_command_outputs_timestamp
    ON command_outputs(timestamp DESC);

-- Agent aliases index
CREATE INDEX IF NOT EXISTS idx_agent_aliases_guid
    ON agent_aliases(guid);

-- User sessions index
CREATE INDEX IF NOT EXISTS idx_user_sessions_username
    ON user_sessions(username);

-- Agent tags indexes (for tag filtering)
CREATE INDEX IF NOT EXISTS idx_agent_tags_guid
    ON agent_tags(agent_guid);

CREATE INDEX IF NOT EXISTS idx_agent_tags_name
    ON agent_tags(tag_name);

-- Link routes indexes (if link functionality is implemented)
CREATE INDEX IF NOT EXISTS idx_link_routes_source
    ON link_routes(source_guid);

CREATE INDEX IF NOT EXISTS idx_link_routes_destination
    ON link_routes(destination_guid);

-- Link routing indexes (for SMB link traffic)
CREATE INDEX IF NOT EXISTS idx_link_routing_edge
    ON link_routing(edge_clientID);

CREATE INDEX IF NOT EXISTS idx_link_routing_linked
    ON link_routing(linked_clientID);

CREATE INDEX IF NOT EXISTS idx_link_routing_lookup
    ON link_routing(edge_clientID, routing_id)
    WHERE status = 'active';

-- Connections parent tracking index (for multi-hop routing)
CREATE INDEX IF NOT EXISTS idx_connections_parent
    ON connections(parent_clientID)
    WHERE parent_clientID IS NOT NULL;

-- API users and tokens indexes (for REST API authentication)
CREATE INDEX IF NOT EXISTS idx_api_users_username
    ON api_users(username);

CREATE INDEX IF NOT EXISTS idx_api_users_active
    ON api_users(is_active)
    WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id
    ON api_tokens(user_id);

CREATE INDEX IF NOT EXISTS idx_api_tokens_expires
    ON api_tokens(expires_at);