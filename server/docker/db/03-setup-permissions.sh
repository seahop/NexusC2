#!/bin/bash
set -e

# Use POSTGRES_PASSWORD which is always available in the init environment
# The operator user will use the same password as set in .env

if [ -z "$POSTGRES_PASSWORD" ]; then
  echo "ERROR: POSTGRES_PASSWORD not available"
  exit 1
fi

echo "Setting up operator user with password from POSTGRES_PASSWORD..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    ALTER USER operator WITH PASSWORD '$POSTGRES_PASSWORD';
    GRANT USAGE, CREATE ON SCHEMA public TO operator;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO operator;
    GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO operator;
    GRANT USAGE, SELECT ON SEQUENCE commands_id_seq TO operator;
    GRANT USAGE, SELECT ON SEQUENCE command_outputs_id_seq TO operator;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO operator;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL PRIVILEGES ON SEQUENCES TO operator;
EOSQL

echo "Operator user permissions configured successfully"
