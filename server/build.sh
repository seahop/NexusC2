#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status
export PATH=$PATH:$HOME/go/bin:/usr/local/go/bin

# Run protoc to generate Go files from .proto definitions
echo "Running protoc to generate Go files from agent.proto..."
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/service/agent.proto
mv proto/service/agent.pb.go proto/
mv proto/service/agent_grpc.pb.go proto/
echo "protoc generation completed successfully."

# Create bin directory if it does not exist
echo "Creating bin directory if it does not exist..."
mkdir -p docker/bin
echo "Creating certs directory if it does not exist..."
mkdir -p docker/bin/certs

echo "Building WebSocket Service..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o docker/bin/websocket-service ./cmd/websocket
echo "WebSocket Service built successfully."

echo "Building Agent-Handler Service..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o docker/bin/agent-handler-service ./cmd/agent-handler
echo "Agent-Handler Service built successfully."

echo "Building Log Analyzer..."
CGO_ENABLED=0 go build -o bin/logviewer cmd/logviewer/main.go
echo "Log Analyzer built successfully"

echo "All services have been built successfully!"

# Copy certificates and configuration files
echo "Copying certificates to docker/bin..."
cp -r ../scripts/certs/ docker/bin
echo "Certificates copied successfully."

echo "Copying configuration file to docker/bin..."
cp config.toml docker/bin
echo "Configuration file copied successfully."

# Copy docker-compose.yml and Dockerfile.builder to docker/bin for the websocket container
echo "Copying docker-compose.yml to docker directory..."
cp docker/docker-compose.yml docker/
echo "Copying Dockerfile.builder to docker directory..."
cp docker/Dockerfile.builder docker/
echo "Docker build files copied successfully."
