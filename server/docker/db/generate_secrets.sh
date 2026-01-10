#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SECRETS_DIR="$SCRIPT_DIR/.secrets"

POSTGRES_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
DB_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
API_PASSWORD=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 64)

# Get docker group GID for socket access in containers
DOCKER_GID=$(getent group docker | cut -d: -f3 || echo "984")

export POSTGRES_PASSWORD
export DB_PASSWORD
export API_PASSWORD
export JWT_SECRET
export DOCKER_GID

mkdir -p "$SECRETS_DIR"

cat > "$SECRETS_DIR/.env" <<EOL
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
DB_PASSWORD=$DB_PASSWORD
API_PASSWORD=$API_PASSWORD
JWT_SECRET=$JWT_SECRET
DOCKER_GID=$DOCKER_GID
EOL

if ! grep -q "POSTGRES_PASSWORD" ~/.bashrc; then
    echo "export POSTGRES_PASSWORD=$POSTGRES_PASSWORD" >> ~/.bashrc
    echo "POSTGRES_PASSWORD added to .bashrc"
fi

if ! grep -q "DB_PASSWORD" ~/.bashrc; then
    echo "export DB_PASSWORD=$DB_PASSWORD" >> ~/.bashrc
    echo "DB_PASSWORD added to .bashrc"
else
    echo "DB_PASSWORD already in .bashrc"
fi

if ! grep -q "API_PASSWORD" ~/.bashrc; then
    echo "export API_PASSWORD=$API_PASSWORD" >> ~/.bashrc
    echo "API_PASSWORD added to .bashrc"
else
    echo "API_PASSWORD already in .bashrc"
fi

echo "Environment variables set in $SECRETS_DIR/.env"
echo "Database and API secrets generated"
echo ""
echo "API Password for REST API authentication: $API_PASSWORD"
echo "(Save this password - you'll need it to authenticate with the REST API)"

# Copy .env to parent docker directory for docker-compose build args
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
cp "$SECRETS_DIR/.env" "$DOCKER_DIR/.env"
echo "Copied .env to $DOCKER_DIR/.env for docker-compose build args"