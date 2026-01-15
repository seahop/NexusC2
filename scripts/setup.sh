#!/bin/bash
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status messages
print_status() {
    echo -e "${GREEN}==>${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}==>${NC} $1"
}

print_error() {
    echo -e "${RED}==>${NC} $1"
}

print_info() {
    echo -e "${BLUE}==>${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: sudo ./setup.sh [OPTIONS]

Setup script for NexusC2 Framework. Run without options to install everything.

All building happens inside Docker containers - no Go, protoc, or build tools
are installed on the host system.

OPTIONS:
    --all           Install everything (default if no options specified)
    --docker        Install Docker only
    --certs         Generate certificates only
    --secrets       Generate database secrets only
    --client        Setup Python client virtual environment only
    --help, -h      Show this help message

EXAMPLES:
    sudo ./setup.sh                    # Install everything
    sudo ./setup.sh --all              # Install everything
    sudo ./setup.sh --certs --secrets  # Only generate certs and secrets
    sudo ./setup.sh --docker           # Only install Docker
    sudo ./setup.sh --client           # Only setup Python client

NOTES:
    - Must be run with sudo
    - You can combine multiple flags to run specific steps
    - Failed steps can be re-run individually without affecting completed steps
    - Building happens in Docker containers, so no Go/protoc needed on host

EOF
}

# Initialize flags
RUN_ALL=false
RUN_DOCKER=false
RUN_CERTS=false
RUN_SECRETS=false
RUN_CLIENT=false

# Parse command line arguments
if [ $# -eq 0 ]; then
    RUN_ALL=true
else
    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                RUN_ALL=true
                shift
                ;;
            --docker)
                RUN_DOCKER=true
                shift
                ;;
            --certs)
                RUN_CERTS=true
                shift
                ;;
            --secrets)
                RUN_SECRETS=true
                shift
                ;;
            --client)
                RUN_CLIENT=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo ""
                show_usage
                exit 1
                ;;
        esac
    done
fi

# Check if script is run with sudo
if [ "$EUID" -ne 0 ]; then
    print_error "Please run with sudo"
    exit 1
fi

# Store the actual username to use later
ACTUAL_USER=$(logname)
print_status "Setting up environment for user: $ACTUAL_USER"

# Get the script's directory to ensure relative paths work correctly
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
print_status "Script directory: $SCRIPT_DIR"

# ============================================================================
# Individual Component Functions
# ============================================================================

install_minimal_packages() {
    print_info "============================================================"
    print_status "Installing Minimal System Packages"
    print_info "============================================================"

    # Create shared directory
    print_status "Creating /shared"
    mkdir -p /shared

    # Update package list
    print_status "Updating package list"
    apt update

    # Install only essential packages (no Go, protoc, or build tools)
    print_status "Installing required packages"
    apt install -y \
        ca-certificates \
        curl \
        gnupg \
        python3-dev \
        python3-pip \
        python3-venv

    print_status "Minimal system packages installed successfully!"
}

install_docker() {
    print_info "============================================================"
    print_status "Installing Docker"
    print_info "============================================================"

    # Check if Docker is already installed
    if command -v docker &> /dev/null; then
        print_status "Docker is already installed"
        docker --version

        # Still ensure user is in docker group
        TARGET_USER="$ACTUAL_USER"
        if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ]; then
            if ! groups "$TARGET_USER" | grep -q '\bdocker\b'; then
                print_status "Adding user '$TARGET_USER' to docker group..."
                usermod -aG docker "$TARGET_USER"
                print_warning "IMPORTANT: You must log out and log back in for docker group changes to take effect!"
            fi
        fi
        return 0
    fi

    # Set up Docker repository
    print_status "Setting up Docker repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker packages
    print_status "Installing Docker packages..."
    apt update
    apt install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin

    # Enable and start Docker service
    print_status "Enabling Docker service to start on boot..."
    systemctl enable docker
    systemctl enable containerd

    print_status "Starting Docker service..."
    systemctl start docker
    systemctl start containerd

    # Add user to docker group with better error handling
    print_status "Adding user to docker group..."

    # Try to get the actual user with multiple fallback methods
    TARGET_USER="$ACTUAL_USER"
    if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
        # Fallback 1: Try SUDO_USER
        TARGET_USER="${SUDO_USER:-}"
    fi
    if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
        # Fallback 2: Get the user who owns /home directory with most recent activity
        TARGET_USER=$(ls -lt /home | grep '^d' | head -n1 | awk '{print $NF}')
    fi

    if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
        print_error "Could not determine non-root user to add to docker group"
        print_error "Please manually run: sudo usermod -aG docker YOUR_USERNAME"
        return 1
    fi

    print_status "Adding user '$TARGET_USER' to docker group..."
    usermod -aG docker "$TARGET_USER"

    # Verify the user was added to docker group
    if groups "$TARGET_USER" | grep -q '\bdocker\b'; then
        print_status "User '$TARGET_USER' successfully added to docker group"
    else
        print_error "Failed to add user '$TARGET_USER' to docker group"
        print_error "Please manually run: sudo usermod -aG docker $TARGET_USER"
        return 1
    fi

    print_status "Docker installed successfully!"
    docker --version

    # Verify Docker is running
    if systemctl is-active --quiet docker; then
        print_status "Docker service is running"
    else
        print_warning "Docker service may not be running properly"
    fi

    # Remind user about logout requirement
    print_warning "IMPORTANT: You must log out and log back in for docker group changes to take effect!"
}

generate_certificates() {
    print_info "============================================================"
    print_status "Generating Certificates"
    print_info "============================================================"

    if [ -f "$SCRIPT_DIR/gen_default_certs.sh" ]; then
        # Ensure client/certs directory exists with correct ownership
        CLIENT_CERTS_DIR="$SCRIPT_DIR/../client/certs"
        mkdir -p "$CLIENT_CERTS_DIR"
        chown -R $ACTUAL_USER:$ACTUAL_USER "$CLIENT_CERTS_DIR"
        print_status "Created client/certs directory"

        # Ensure server/certs directory exists (new location for containerized build)
        SERVER_CERTS_DIR="$SCRIPT_DIR/../server/certs"
        mkdir -p "$SERVER_CERTS_DIR"
        print_status "Created server/certs directory"

        cd "$SCRIPT_DIR"
        bash gen_default_certs.sh

        # Fix permissions so Docker can read the certs
        CERTS_DIR="$SCRIPT_DIR/certs"
        if [ -d "$CERTS_DIR" ]; then
            chown -R $ACTUAL_USER:$ACTUAL_USER "$CERTS_DIR"
            chmod -R 644 "$CERTS_DIR"/*.key "$CERTS_DIR"/*.crt 2>/dev/null || true
            print_status "Fixed certificate permissions"
        fi

        # Copy certificates to server/certs for Docker build context
        if [ -d "$CERTS_DIR" ]; then
            print_status "Copying certificates to server/certs for Docker build..."
            cp "$CERTS_DIR"/*.crt "$SERVER_CERTS_DIR/" 2>/dev/null || true
            cp "$CERTS_DIR"/*.key "$SERVER_CERTS_DIR/" 2>/dev/null || true
            chown -R $ACTUAL_USER:$ACTUAL_USER "$SERVER_CERTS_DIR"
            chmod -R 644 "$SERVER_CERTS_DIR"/*.key "$SERVER_CERTS_DIR"/*.crt 2>/dev/null || true
            print_status "Certificates copied to server/certs"
        fi

        print_status "Certificates generated successfully!"
    else
        print_error "Certificate generation script not found at: $SCRIPT_DIR/gen_default_certs.sh"
        print_warning "Skipping certificate generation."
        return 1
    fi
}

generate_secrets() {
    print_info "============================================================"
    print_status "Generating Database Secrets"
    print_info "============================================================"

    DB_SECRETS_SCRIPT="$SCRIPT_DIR/../server/docker/db/generate_secrets.sh"
    if [ -f "$DB_SECRETS_SCRIPT" ]; then
        bash "$DB_SECRETS_SCRIPT"
        print_status "Database secrets generated successfully!"
    else
        print_error "Database secrets script not found at: $DB_SECRETS_SCRIPT"
        print_warning "Skipping database secrets generation."
        return 1
    fi
}

setup_docker_permissions() {
    print_info "============================================================"
    print_status "Setting Docker Volume Permissions"
    print_info "============================================================"

    DOCKER_DIR="$SCRIPT_DIR/../server/docker"

    if [ -d "$DOCKER_DIR" ]; then
        cd "$DOCKER_DIR"

        # Create directories if they don't exist
        print_status "Creating Docker volume directories..."
        mkdir -p downloads uploads temp logs

        # Set ownership for agent-handler (UID 1001)
        # These directories are mounted as volumes in docker-compose.yml
        print_status "Setting ownership for agent-handler volumes (UID 1001)..."
        chown -R 1001:1001 downloads uploads temp logs

        print_status "Docker volume permissions set successfully!"
        print_info "  - downloads, uploads, temp, logs: 1001:1001 (agent-handler)"

        cd "$SCRIPT_DIR"
        return 0
    else
        print_error "Docker directory not found at: $DOCKER_DIR"
        print_warning "Skipping permission setup."
        return 1
    fi
}

setup_firewall_rules() {
    print_info "============================================================"
    print_status "Setting Up Firewall Rules"
    print_info "============================================================"

    FIREWALL_SCRIPT="$SCRIPT_DIR/../server/docker/setup-firewall.sh"

    # First, secure the gRPC port
    if [ -f "$FIREWALL_SCRIPT" ]; then
        print_status "Applying firewall rules to secure gRPC port 50051..."
        bash "$FIREWALL_SCRIPT"

        if [ $? -eq 0 ]; then
            print_status "gRPC firewall rules applied successfully!"
            print_info "  - Port 50051: Blocked from external networks"
            print_info "  - Port 50051: Accessible from localhost and Docker containers"
        else
            print_error "Failed to apply gRPC firewall rules"
            print_warning "gRPC port 50051 may be exposed to external networks!"
        fi
    else
        print_warning "Firewall script not found at: $FIREWALL_SCRIPT"
        print_warning "Skipping gRPC firewall setup."
    fi

    # Open WebSocket port (3131) for external client connections
    print_status "Opening WebSocket port 3131 for external client connections..."

    # Check if ufw is available and active
    if command -v ufw &> /dev/null; then
        UFW_STATUS=$(ufw status 2>/dev/null | head -1)
        if [[ "$UFW_STATUS" == *"active"* ]]; then
            print_status "UFW is active, adding rule for port 3131..."
            ufw allow 3131/tcp comment 'NexusC2 WebSocket'
            print_status "UFW rule added for port 3131"
        else
            print_info "UFW is installed but not active, skipping UFW rule"
        fi
    fi

    # Also add iptables rule for systems not using ufw
    # Check if there's already a rule for port 3131
    if ! iptables -C INPUT -p tcp --dport 3131 -j ACCEPT &>/dev/null 2>&1; then
        print_status "Adding iptables rule to allow port 3131..."
        iptables -I INPUT -p tcp --dport 3131 -j ACCEPT
        print_status "iptables rule added for port 3131"
    else
        print_info "iptables rule for port 3131 already exists"
    fi

    print_status "Firewall configuration complete!"
    print_info "  - Port 3131 (WebSocket): Open for external client connections"
    print_info "  - Port 50051 (gRPC): Restricted to localhost and Docker"
    return 0
}

setup_python_client() {
    print_info "============================================================"
    print_status "Setting up Python Client"
    print_info "============================================================"

    CLIENT_DIR="$SCRIPT_DIR/../client"
    CLIENT_REQUIREMENTS="$CLIENT_DIR/requirements.txt"

    if [ -d "$CLIENT_DIR" ] && [ -f "$CLIENT_REQUIREMENTS" ]; then
        # Check if running with --client flag (non-interactive) or as part of --all (interactive)
        if [ "$RUN_CLIENT" = true ] && [ "$RUN_ALL" = false ]; then
            # Non-interactive mode - just do it
            setup_venv="y"
        else
            # Interactive mode
            read -p "Would you like to set up the Python client virtual environment? (y/n): " setup_venv
        fi

        if [[ "$setup_venv" =~ ^[Yy]$ ]]; then
            print_status "Setting up Python virtual environment for client..."

            # Change to client directory
            cd "$CLIENT_DIR"

            # Remove old venv if it exists
            if [ -d "venv" ]; then
                print_status "Removing existing virtual environment..."
                rm -rf venv
            fi

            # Create virtual environment as the actual user (not root)
            print_status "Creating virtual environment..."
            sudo -u $ACTUAL_USER python3 -m venv venv

            # Install requirements
            print_status "Installing Python requirements..."
            sudo -u $ACTUAL_USER bash -c "source venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt"

            cd "$SCRIPT_DIR"
            print_status "Python virtual environment setup complete!"
            return 0
        else
            print_warning "Skipping Python client setup."
            return 1
        fi
    else
        print_error "Client directory or requirements.txt not found at: $CLIENT_DIR"
        print_warning "Skipping Python client setup."
        return 1
    fi
}

# ============================================================================
# Execute Based on Flags
# ============================================================================

# Track what was run
SUMMARY_ITEMS=()

if [ "$RUN_ALL" = true ]; then
    print_info "============================================================"
    print_status "Running Full Setup (Containerized Build)"
    print_info "============================================================"
    print_info "Note: All building happens in Docker containers - no Go/protoc on host"
    echo ""

    install_minimal_packages && SUMMARY_ITEMS+=("System packages installed") || SUMMARY_ITEMS+=("System packages failed")
    echo ""

    install_docker && SUMMARY_ITEMS+=("Docker installed and configured") || SUMMARY_ITEMS+=("Docker installation failed")
    SUMMARY_ITEMS+=("User added to docker group")
    echo ""

    generate_certificates && SUMMARY_ITEMS+=("Certificates generated") || SUMMARY_ITEMS+=("Certificate generation failed")
    echo ""

    generate_secrets && SUMMARY_ITEMS+=("Database secrets generated") || SUMMARY_ITEMS+=("Secret generation failed")
    echo ""

    setup_docker_permissions && SUMMARY_ITEMS+=("Docker volume permissions set") || SUMMARY_ITEMS+=("Docker permissions setup failed")
    echo ""

    setup_firewall_rules && SUMMARY_ITEMS+=("Firewall rules applied (gRPC secured)") || SUMMARY_ITEMS+=("Firewall rules not applied (manual setup required)")
    echo ""

    if setup_python_client; then
        SUMMARY_ITEMS+=("Python client virtual environment created")
    fi
    echo ""
else
    # Run individual components based on flags
    [ "$RUN_DOCKER" = true ] && { install_minimal_packages; install_docker && SUMMARY_ITEMS+=("Docker installed and configured") || SUMMARY_ITEMS+=("Docker installation failed"); echo ""; }
    [ "$RUN_CERTS" = true ] && { generate_certificates && SUMMARY_ITEMS+=("Certificates generated") || SUMMARY_ITEMS+=("Certificate generation failed"); echo ""; }
    [ "$RUN_SECRETS" = true ] && { generate_secrets && SUMMARY_ITEMS+=("Database secrets generated") || SUMMARY_ITEMS+=("Secret generation failed"); echo ""; }
    [ "$RUN_CLIENT" = true ] && { setup_python_client && SUMMARY_ITEMS+=("Python client virtual environment created") || SUMMARY_ITEMS+=("Python client setup failed"); echo ""; }
fi

# Check if client venv exists
CLIENT_VENV_EXISTS=false
if [ -d "$SCRIPT_DIR/../client/venv" ]; then
    CLIENT_VENV_EXISTS=true
fi

echo ""
print_info "============================================================"
print_status "Setup Summary"
print_info "============================================================"
echo ""

# Print summary items
for item in "${SUMMARY_ITEMS[@]}"; do
    echo "  - $item"
done

echo ""
print_info "============================================================"
print_status "Next Steps"
print_info "============================================================"
echo ""

STEP_NUM=1

# Only show logout message if Docker was installed
if [[ "$RUN_ALL" = true ]] || [[ "$RUN_DOCKER" = true ]]; then
    echo "  ${STEP_NUM}. Log out and log back in (for docker group changes to take effect)"
    ((STEP_NUM++))
fi

echo "  ${STEP_NUM}. Start the server services (first run will build containers):"
echo "     cd $SCRIPT_DIR/../server/docker"
echo "     docker compose up -d"
echo ""
echo "     Note: First run will take a few minutes to build Go binaries in containers"
echo ""
((STEP_NUM++))

if [ "$CLIENT_VENV_EXISTS" = false ]; then
    echo "  ${STEP_NUM}. Set up the client (if not done already):"
    echo "     cd $SCRIPT_DIR/../client"
    echo "     python3 -m venv venv"
    echo "     source venv/bin/activate"
    echo "     pip install -r requirements.txt"
    echo "     OR run: sudo $SCRIPT_DIR/setup.sh --client"
    echo ""
    ((STEP_NUM++))
fi

echo "  ${STEP_NUM}. Start the client:"
echo "     cd $SCRIPT_DIR/../client"
echo "     source venv/bin/activate"
echo "     python src/main.py"
echo ""

print_status "For more information, check the README.md file."
print_status "To re-run specific parts, use: sudo ./setup.sh --help"
print_info "============================================================"
