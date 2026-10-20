#!/bin/bash
set -e

# Use DB_PASSWORD for the operator user (separate from POSTGRES_PASSWORD for the superuser)
# DB_PASSWORD comes from the .env file passed via env_file in docker-compose

if [ -z "$DB_PASSWORD" ]; then
  echo "ERROR: DB_PASSWORD not available"
  exit 1
fi

echo "Setting up operator user with password from DB_PASSWORD..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    ALTER USER operator WITH PASSWORD '$DB_PASSWORD';
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
