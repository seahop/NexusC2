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

Setup script for C2 Framework. Run without options to install everything.

OPTIONS:
    --all           Install everything (default if no options specified)
    --packages      Install system packages only
    --go            Install Go only
    --protoc        Install Protocol Buffers compiler only
    --docker        Install Docker only
    --certs         Generate certificates only
    --secrets       Generate database secrets only
    --build         Build server binaries only
    --client        Setup Python client virtual environment only
    --help, -h      Show this help message

EXAMPLES:
    sudo ./setup.sh                    # Install everything
    sudo ./setup.sh --all              # Install everything
    sudo ./setup.sh --certs --secrets  # Only generate certs and secrets
    sudo ./setup.sh --build            # Only build server binaries
    sudo ./setup.sh --client           # Only setup Python client

NOTES:
    - Must be run with sudo
    - You can combine multiple flags to run specific steps
    - Failed steps can be re-run individually without affecting completed steps

EOF
}

# Initialize flags
RUN_ALL=false
RUN_PACKAGES=false
RUN_GO=false
RUN_PROTOC=false
RUN_DOCKER=false
RUN_CERTS=false
RUN_SECRETS=false
RUN_BUILD=false
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
            --packages)
                RUN_PACKAGES=true
                shift
                ;;
            --go)
                RUN_GO=true
                shift
                ;;
            --protoc)
                RUN_PROTOC=true
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
            --build)
                RUN_BUILD=true
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

install_packages() {
    print_info "============================================================"
    print_status "Installing System Packages"
    print_info "============================================================"
    
    # Create shared directory
    print_status "Creating /shared"
    mkdir -p /shared
    
    # Update package list
    print_status "Updating package list"
    apt update
    
    # Install all required packages in one go
    print_status "Installing required packages"
    apt install -y \
        open-vm-tools-desktop \
        postgresql-client \
        ca-certificates \
        curl \
        gnupg \
        pipx \
        python3-dev \
        python3-pip \
        python3-venv \
        build-essential \
        docker-compose \
        unzip
    
    print_status "System packages installed successfully!"
}

install_go() {
    print_info "============================================================"
    print_status "Installing Go"
    print_info "============================================================"
    
    # Pin to specific Go version for stability
    GO_VERSION="go1.25.4"
    REQUIRED_VERSION="1.25.4"
    
    # Check if Go is already installed with the correct version
    if command -v go &> /dev/null; then
        CURRENT_VERSION=$(go version | grep -oP 'go\K[0-9.]+')
        print_status "Found existing Go installation: ${CURRENT_VERSION}"
        
        if [ "$CURRENT_VERSION" = "$REQUIRED_VERSION" ]; then
            print_status "Go ${REQUIRED_VERSION} is already installed. Skipping installation."
            return 0
        else
            print_status "Current version (${CURRENT_VERSION}) differs from required (${REQUIRED_VERSION})"
            print_status "Proceeding with installation of Go ${GO_VERSION}..."
        fi
    fi
    
    print_status "Downloading Go ${GO_VERSION}..."
    wget "https://golang.org/dl/${GO_VERSION}.linux-amd64.tar.gz"
    
    if [ $? -ne 0 ]; then
        print_error "Failed to download Go ${GO_VERSION}"
        print_error "Please check if the version exists at https://go.dev/dl/"
        exit 1
    fi
    
    print_status "Installing Go..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${GO_VERSION}.linux-amd64.tar.gz"
    rm "${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add to bashrc if not already present
    if ! grep -q "/usr/local/go/bin" /home/$ACTUAL_USER/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/$ACTUAL_USER/.bashrc
        print_status "Added Go to PATH in .bashrc"
    else
        print_status "Go already in PATH"
    fi
    
    # Temporarily set PATH for this script
    export PATH=$PATH:/usr/local/go/bin
    
    print_status "Go ${GO_VERSION} installed successfully!"
    /usr/local/go/bin/go version
}

install_protoc() {
    print_info "============================================================"
    print_status "Installing Protocol Buffers Compiler (protoc)"
    print_info "============================================================"
    
    PROTOC_VERSION=$(curl -s https://api.github.com/repos/protocolbuffers/protobuf/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/v//')
    print_status "Downloading protoc ${PROTOC_VERSION}..."
    wget "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    
    print_status "Installing protoc..."
    unzip -o "protoc-${PROTOC_VERSION}-linux-x86_64.zip" -d /usr/local bin/protoc
    unzip -o "protoc-${PROTOC_VERSION}-linux-x86_64.zip" -d /usr/local 'include/*'
    chmod +x /usr/local/bin/protoc
    rm "protoc-${PROTOC_VERSION}-linux-x86_64.zip"
    
    # Ensure Go is in PATH for installing plugins
    export PATH=$PATH:/usr/local/go/bin
    
    print_status "Installing protoc Go plugins..."
    GOBIN=/usr/local/go/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    GOBIN=/usr/local/go/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    
    print_status "Protocol Buffers Compiler installed successfully!"
    protoc --version
}

install_docker() {
    print_info "============================================================"
    print_status "Installing Docker"
    print_info "============================================================"
    
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
        print_status "User '$TARGET_USER' successfully added to docker group ✓"
    else
        print_error "Failed to add user '$TARGET_USER' to docker group"
        print_error "Please manually run: sudo usermod -aG docker $TARGET_USER"
        return 1
    fi
    
    print_status "Docker installed successfully!"
    docker --version
    
    # Verify Docker is running
    if systemctl is-active --quiet docker; then
        print_status "Docker service is running ✓"
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
        
        cd "$SCRIPT_DIR"
        bash gen_default_certs.sh
        
        # Fix permissions so the actual user can read the certs for building
        CERTS_DIR="$SCRIPT_DIR/certs"
        if [ -d "$CERTS_DIR" ]; then
            chown -R $ACTUAL_USER:$ACTUAL_USER "$CERTS_DIR"
            chmod -R 644 "$CERTS_DIR"/*.key "$CERTS_DIR"/*.crt 2>/dev/null || true
            print_status "Fixed certificate permissions for build process"
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

build_server_binaries() {
    print_info "============================================================"
    print_status "Building Server Binaries"
    print_info "============================================================"
    
    SERVER_BUILD_SCRIPT="$SCRIPT_DIR/../server/build.sh"
    SERVER_DIR="$SCRIPT_DIR/../server"
    
    if [ -f "$SERVER_BUILD_SCRIPT" ] && [ -d "$SERVER_DIR" ]; then
        print_status "Found build script, compiling server binaries..."
        # Change to server directory and run build as the actual user
        cd "$SERVER_DIR"
        # Run the build script (ignore exit code, we'll check for binaries instead)
        sudo -u $ACTUAL_USER bash build.sh || true
        
        # Check if binaries were actually created (this is more reliable than exit code)
        if [ -f "docker/bin/websocket-service" ] && [ -f "docker/bin/agent-handler-service" ]; then
            print_status "Server binaries built successfully!"
            cd "$SCRIPT_DIR"
            return 0
        else
            print_error "Build script ran but binaries not found"
            cd "$SCRIPT_DIR"
            return 1
        fi
    else
        print_error "Server build script not found at: $SERVER_BUILD_SCRIPT"
        print_warning "Skipping binary build."
        return 1
    fi
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
    print_status "Running Full Setup"
    print_info "============================================================"
    echo ""
    
    install_packages && SUMMARY_ITEMS+=("✓ System packages installed") || SUMMARY_ITEMS+=("✗ System packages failed")
    echo ""
    
    install_go && SUMMARY_ITEMS+=("✓ Go installed") || SUMMARY_ITEMS+=("✗ Go installation failed")
    echo ""
    
    install_protoc && SUMMARY_ITEMS+=("✓ Protocol Buffers compiler installed") || SUMMARY_ITEMS+=("✗ Protoc installation failed")
    echo ""
    
    install_docker && SUMMARY_ITEMS+=("✓ Docker installed and configured") || SUMMARY_ITEMS+=("✗ Docker installation failed")
    SUMMARY_ITEMS+=("✓ User added to docker group")
    echo ""
    
    generate_certificates && SUMMARY_ITEMS+=("✓ Certificates generated") || SUMMARY_ITEMS+=("✗ Certificate generation failed")
    echo ""
    
    generate_secrets && SUMMARY_ITEMS+=("✓ Database secrets generated") || SUMMARY_ITEMS+=("✗ Secret generation failed")
    echo ""
    
    if build_server_binaries; then
        SUMMARY_ITEMS+=("✓ Server binaries built")
    else
        SUMMARY_ITEMS+=("⚠ Server binaries not built (may need manual build)")
    fi
    echo ""
    
    if setup_python_client; then
        SUMMARY_ITEMS+=("✓ Python client virtual environment created")
    fi
    echo ""
else
    # Run individual components based on flags
    [ "$RUN_PACKAGES" = true ] && { install_packages && SUMMARY_ITEMS+=("✓ System packages installed") || SUMMARY_ITEMS+=("✗ System packages failed"); echo ""; }
    [ "$RUN_GO" = true ] && { install_go && SUMMARY_ITEMS+=("✓ Go installed") || SUMMARY_ITEMS+=("✗ Go installation failed"); echo ""; }
    [ "$RUN_PROTOC" = true ] && { install_protoc && SUMMARY_ITEMS+=("✓ Protocol Buffers compiler installed") || SUMMARY_ITEMS+=("✗ Protoc installation failed"); echo ""; }
    [ "$RUN_DOCKER" = true ] && { install_docker && SUMMARY_ITEMS+=("✓ Docker installed and configured") || SUMMARY_ITEMS+=("✗ Docker installation failed"); echo ""; }
    [ "$RUN_CERTS" = true ] && { generate_certificates && SUMMARY_ITEMS+=("✓ Certificates generated") || SUMMARY_ITEMS+=("✗ Certificate generation failed"); echo ""; }
    [ "$RUN_SECRETS" = true ] && { generate_secrets && SUMMARY_ITEMS+=("✓ Database secrets generated") || SUMMARY_ITEMS+=("✗ Secret generation failed"); echo ""; }
    [ "$RUN_BUILD" = true ] && { build_server_binaries && SUMMARY_ITEMS+=("✓ Server binaries built") || SUMMARY_ITEMS+=("✗ Server binary build failed"); echo ""; }
    [ "$RUN_CLIENT" = true ] && { setup_python_client && SUMMARY_ITEMS+=("✓ Python client virtual environment created") || SUMMARY_ITEMS+=("✗ Python client setup failed"); echo ""; }
fi

# ============================================================================
# Final Summary
# ============================================================================

# Check if binaries exist
BINARIES_BUILT=false
if [ -f "$SCRIPT_DIR/../server/docker/bin/websocket-service" ] && [ -f "$SCRIPT_DIR/../server/docker/bin/agent-handler-service" ]; then
    BINARIES_BUILT=true
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
    echo "  $item"
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

# Show build step only if binaries don't exist and build wasn't just run
if [ "$BINARIES_BUILT" = false ]; then
    echo "  ${STEP_NUM}. Build the server binaries:"
    echo "     cd $SCRIPT_DIR/../server"
    echo "     ./build.sh"
    echo "     OR run: sudo $SCRIPT_DIR/setup.sh --build"
    echo ""
    ((STEP_NUM++))
fi

echo "  ${STEP_NUM}. Start the server services:"
echo "     cd $SCRIPT_DIR/../server/docker"
echo "     docker-compose up -d"
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
echo "     cd src"
echo "     python src/main.py"
echo ""

print_status "For more information, check the README.md file."
print_status "To re-run specific parts, use: sudo ./setup.sh --help"
print_info "============================================================"