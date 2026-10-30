# Remote Builder

The remote builder lets you offload payload compilation to a separate machine so the primary C2 host isn't burdened with CPU-intensive Go builds. Communication between the C2 server and the remote builder is secured with mutual TLS (mTLS) using TLS 1.3.

## Architecture

```
┌─────────────────┐       mTLS (TLS 1.3)       ┌──────────────────────┐
│   C2 Server     │ ──────────────────────────► │  Remote Builder      │
│                 │  POST /api/v1/build         │                      │
│  config.toml    │  ◄────────────────────────  │  Runs docker_builder │
│  mode = remote  │       binary stream         │  container locally   │
└─────────────────┘                             └──────────────────────┘
```

When `mode = "remote"` in `config.toml`, both the REST API and WebSocket services send build requests to the remote builder instead of spawning a local Docker container. The remote builder runs the same `docker_builder:latest` image and streams the compiled binary back over the mTLS connection.

## Prerequisites

**Remote builder machine:**
- Docker installed and running
- Port 9443 open (or your chosen port)
- The `docker_builder:latest` image (built automatically on first use, or pre-built)
- Payload source templates in `./payloads/`

**C2 server:**
- No additional requirements beyond config changes

## Quick Start

### 1. Generate mTLS Certificates

From the project root:

```bash
./scripts/gen_remote_builder_certs.sh certs/remote-builder <REMOTE_IP>
```

Replace `<REMOTE_IP>` with the remote builder's IP address or hostname. This creates:

| File | Location | Purpose |
|------|----------|---------|
| `ca.crt` | Both machines | CA certificate for verification |
| `ca.key` | Keep offline | CA private key (not deployed) |
| `server.crt` | Remote builder | Server identity certificate |
| `server.key` | Remote builder | Server private key |
| `client.crt` | C2 server | Client identity certificate |
| `client.key` | C2 server | Client private key |

### 2. Deploy the Remote Builder

**Option A: Docker Compose (recommended)**

On the remote machine:

```bash
# Create working directory
mkdir -p /opt/nexus/{certs,shared,payloads}

# Copy certificates
scp certs/remote-builder/ca.crt certs/remote-builder/server.crt certs/remote-builder/server.key \
    user@remote:/opt/nexus/certs/

# Copy payload templates
scp -r server/docker/payloads/* user@remote:/opt/nexus/payloads/

# Copy compose file and Dockerfiles
scp server/docker/docker-compose.remote-builder.yml user@remote:/opt/nexus/docker-compose.yml
scp server/docker/Dockerfile.remote-builder user@remote:/opt/nexus/
scp server/docker/Dockerfile.builder user@remote:/opt/nexus/

# On the remote machine:
cd /opt/nexus
export COMPOSE_DIR=/opt/nexus
docker compose up -d
```

**Option B: Standalone binary**

Build and copy the binary:

```bash
# Build inside Docker (no Go needed on host)
docker run --rm -v $(pwd)/server:/src -w /src golang:1.27-alpine \
    sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /src/remote-builder ./cmd/remote-builder'

scp server/remote-builder user@remote:/opt/nexus/
scp certs/remote-builder/{ca.crt,server.crt,server.key} user@remote:/opt/nexus/certs/
```

On the remote machine:

```bash
./remote-builder \
    --listen :9443 \
    --ca-cert /opt/nexus/certs/ca.crt \
    --server-cert /opt/nexus/certs/server.crt \
    --server-key /opt/nexus/certs/server.key
```

### 3. Configure the C2 Server

Edit `server/config.toml`:

```toml
[builder]
mode = "remote"

[builder.remote]
address = "https://<REMOTE_IP>:9443"
ca_cert = "certs/remote-builder/ca.crt"
client_cert = "certs/remote-builder/client.crt"
client_key = "certs/remote-builder/client.key"
timeout = "10m"
```

Restart the C2 services. Build requests will now be forwarded to the remote builder.

### 4. Verify

Check the remote builder health:

```bash
curl -k https://<REMOTE_IP>:9443/health
```

The C2 server logs will show:
```
Builder initialized in "remote" mode
```

## Configuration Reference

### config.toml `[builder]` Section

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | `"local"` | `"local"` or `"remote"` |
| `remote.address` | string | — | Remote builder URL (e.g., `https://10.0.0.50:9443`) |
| `remote.ca_cert` | string | — | Path to CA certificate |
| `remote.client_cert` | string | — | Path to client certificate |
| `remote.client_key` | string | — | Path to client private key |
| `remote.timeout` | string | `"10m"` | Build timeout (Go duration format) |

### Remote Builder CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:9443` | Listen address |
| `--ca-cert` | `/app/certs/ca.crt` | CA certificate for client verification |
| `--server-cert` | `/app/certs/server.crt` | Server TLS certificate |
| `--server-key` | `/app/certs/server.key` | Server TLS private key |

### Environment Variables (Docker)

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST_PAYLOADS_PATH` | `/app/payloads` | Host path to payload source templates |
| `HOST_SHARED_PATH` | `/shared` | Host path to shared output directory |

## Security

- **mTLS with TLS 1.3 minimum** — both sides authenticate via certificates signed by the same CA
- **No passwords or tokens** — identity is entirely certificate-based
- **Client CN logging** — every build request logs the client certificate's Common Name
- **Minimal attack surface** — the remote builder exposes only two endpoints: `/api/v1/build` (POST) and `/health` (GET)
- **Certificate rotation** — regenerate certs with the script and restart both services; no downtime coordination needed beyond file replacement

## Switching Back to Local

Set `mode = "local"` (or remove the `[builder]` section entirely) in `config.toml` and restart. No other changes needed — the remote builder can stay running for future use.

## Troubleshooting

**"remote build request failed: tls: failed to verify certificate"**
- Verify the CA cert on the C2 server matches the one that signed the remote builder's server cert
- Check that the remote builder's server cert includes the correct IP/DNS SAN

**"remote build request failed: connection refused"**
- Verify the remote builder is running: `curl -k https://<IP>:9443/health`
- Check firewall rules allow port 9443

**"build failed with exit code 1"**
- The Docker build inside the remote builder failed — check remote builder logs
- Ensure `docker_builder:latest` image exists or can be built on the remote machine
- Verify payload templates are mounted correctly

**Timeout errors**
- Increase `timeout` in `config.toml` (default 10 minutes)
- Check network latency between the two machines
- Large payloads (especially Windows with garble obfuscation) can take several minutes
