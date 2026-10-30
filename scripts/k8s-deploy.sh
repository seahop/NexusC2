#!/usr/bin/env bash
set -euo pipefail

# NexusC2 Kubernetes Deployment Script
# Deploys the full C2 stack to a k3s cluster on a single node.
# Requires: Docker, sudo access. Installs k3s if not present.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K8S_DIR="$PROJECT_ROOT/k8s"
DOCKER_DIR="$PROJECT_ROOT/server/docker"
NAMESPACE="nexusc2"
DATA_DIR="/opt/nexusc2"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

# ---- 1. Install k3s if missing ----
install_k3s() {
    if command -v k3s &>/dev/null; then
        log "k3s already installed: $(k3s --version | head -1)"
        return
    fi
    log "Installing k3s..."
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--disable=traefik --write-kubeconfig-mode=644" sh -
    log "Waiting for k3s to be ready..."
    local tries=0
    until sudo k3s kubectl get nodes &>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            err "k3s failed to start after 30 attempts"
            exit 1
        fi
        sleep 2
    done
    log "k3s is ready"
}

# ---- 2. Build Docker images ----
build_images() {
    log "Building Docker images..."
    cd "$DOCKER_DIR"

    docker compose build database 2>&1 | tail -5
    log "  database image built"

    docker compose build agent-handler 2>&1 | tail -5
    log "  agent-handler image built"

    docker compose build websocket 2>&1 | tail -5
    log "  websocket image built"

    docker compose build rest-api 2>&1 | tail -5
    log "  rest-api image built"

    docker compose build builder 2>&1 | tail -5
    log "  builder image (docker_builder:latest) built"
}

# ---- 3. Import images into k3s containerd ----
import_images() {
    log "Importing images into k3s..."
    for img in docker-database docker-agent-handler docker-websocket docker-rest-api docker_builder; do
        log "  importing $img..."
        docker save "docker.io/library/${img}:latest" | sudo k3s ctr images import -
    done
    log "All images imported"
}

# ---- 4. Set up host directories and payloads ----
setup_host_dirs() {
    log "Setting up host directories..."
    sudo mkdir -p "$DATA_DIR"/{shared,payloads}
    sudo cp -r "$DOCKER_DIR/payloads/Darwin" "$DATA_DIR/payloads/" 2>/dev/null || true
    sudo cp -r "$DOCKER_DIR/payloads/Linux"  "$DATA_DIR/payloads/" 2>/dev/null || true
    sudo cp -r "$DOCKER_DIR/payloads/Windows" "$DATA_DIR/payloads/" 2>/dev/null || true
    sudo cp -r "$DOCKER_DIR/payloads/shared" "$DATA_DIR/payloads/" 2>/dev/null || true
    sudo chmod -R 755 "$DATA_DIR"
    log "Payload templates copied to $DATA_DIR/payloads/"
}

# ---- 5. Generate secrets ----
generate_secrets() {
    log "Generating k8s secrets..."

    local pg_pass db_pass api_pass jwt_secret
    pg_pass="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
    db_pass="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
    api_pass="$(openssl rand -base64 24 | tr -d '/+=' | head -c 32)"
    jwt_secret="$(openssl rand -base64 48 | tr -d '/+=' | head -c 64)"

    sudo k3s kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | sudo k3s kubectl apply -f -

    sudo k3s kubectl -n "$NAMESPACE" create secret generic db-secrets \
        --from-literal=POSTGRES_PASSWORD="$pg_pass" \
        --from-literal=DB_PASSWORD="$db_pass" \
        --from-literal=API_PASSWORD="$api_pass" \
        --from-literal=JWT_SECRET="$jwt_secret" \
        --dry-run=client -o yaml | sudo k3s kubectl apply -f -

    log "Secrets created in namespace $NAMESPACE"
}

# ---- 6. Fix pg_hba.conf for k8s pod network ----
create_pg_hba_configmap() {
    log "Creating PostgreSQL network config..."
    sudo k3s kubectl -n "$NAMESPACE" create configmap pg-hba \
        --from-literal=custom-pg_hba.conf="$(cat <<'PGEOF'
# TYPE  DATABASE  USER  ADDRESS       METHOD
host    all       all   10.0.0.0/8    scram-sha-256
host    all       all   172.16.0.0/12 scram-sha-256
local   all       all                 scram-sha-256
host    all       all   127.0.0.1/32  scram-sha-256
host    all       all   ::1/128       scram-sha-256
PGEOF
)" \
        --dry-run=client -o yaml | sudo k3s kubectl apply -f -
}

# ---- 7. Deploy manifests ----
deploy() {
    log "Deploying k8s manifests..."
    sudo k3s kubectl apply -f "$K8S_DIR/namespace.yaml"
    sudo k3s kubectl apply -f "$K8S_DIR/postgres.yaml"

    log "Waiting for database to be ready..."
    sudo k3s kubectl -n "$NAMESPACE" rollout status statefulset/database --timeout=120s || {
        warn "Database rollout timed out, checking pod status..."
        sudo k3s kubectl -n "$NAMESPACE" get pods -l app=database
        sudo k3s kubectl -n "$NAMESPACE" describe pod -l app=database | tail -20
    }

    sudo k3s kubectl apply -f "$K8S_DIR/agent-handler.yaml"
    log "Waiting for agent-handler..."
    sleep 5

    sudo k3s kubectl apply -f "$K8S_DIR/websocket.yaml"
    log "Waiting for websocket..."
    sudo k3s kubectl -n "$NAMESPACE" rollout status deployment/websocket --timeout=120s || true

    sudo k3s kubectl apply -f "$K8S_DIR/rest-api.yaml"
    log "Waiting for rest-api..."
    sudo k3s kubectl -n "$NAMESPACE" rollout status deployment/rest-api --timeout=120s || true

    log "Deployment complete"
}

# ---- 8. Show status ----
show_status() {
    echo ""
    log "=== Deployment Status ==="
    sudo k3s kubectl -n "$NAMESPACE" get pods -o wide
    echo ""
    sudo k3s kubectl -n "$NAMESPACE" get svc
    echo ""
    log "=== Access ==="
    local node_ip
    node_ip="$(hostname -I | awk '{print $1}')"
    echo "  WebSocket: wss://${node_ip}:31310"
    echo "  REST API:  https://${node_ip}:30843"
    echo "  gRPC:      ${node_ip}:50051 (host network)"
    echo ""
    log "From your local machine, use SSH tunnel:"
    echo "  ssh -L 3131:localhost:31310 -L 8443:localhost:30843 <user>@<vm-ip>"
}

# ---- Main ----
main() {
    log "NexusC2 Kubernetes Deployment"
    echo ""

    case "${1:-deploy}" in
        deploy)
            install_k3s
            build_images
            import_images
            setup_host_dirs
            generate_secrets
            create_pg_hba_configmap
            deploy
            show_status
            ;;
        images)
            build_images
            import_images
            ;;
        redeploy)
            deploy
            show_status
            ;;
        status)
            show_status
            ;;
        teardown)
            warn "Tearing down NexusC2 k8s deployment..."
            sudo k3s kubectl delete namespace "$NAMESPACE" --ignore-not-found
            log "Namespace deleted"
            ;;
        *)
            echo "Usage: $0 {deploy|images|redeploy|status|teardown}"
            exit 1
            ;;
    esac
}

main "$@"
