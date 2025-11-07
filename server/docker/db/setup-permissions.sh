#!/bin/bash
set -e

# Verify that the password is provided as an argument
if [ -z "$1" ]; then
  echo "ERROR: DB password not provided."
  exit 1
fi

DB_PASSWORD=$1

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
