#!/bin/bash
# Generate mTLS certificates for the remote builder.
#
# Creates a private CA, a server cert (for the remote builder),
# and a client cert (for the C2 server to authenticate with).
#
# Usage:
#   ./scripts/gen_remote_builder_certs.sh [output_dir] [remote_ip_or_dns]
#
# Example:
#   ./scripts/gen_remote_builder_certs.sh certs/remote-builder 10.0.0.50

set -euo pipefail

OUT_DIR="${1:-certs/remote-builder}"
REMOTE_HOST="${2:-}"

mkdir -p "$OUT_DIR"

DAYS=825
RSA_BITS=4096

echo "=== Generating Remote Builder mTLS Certificates ==="
echo "Output: $OUT_DIR"

# --- CA ---
echo "[1/3] Generating CA..."
openssl genpkey -algorithm RSA -out "$OUT_DIR/ca.key" -pkeyopt rsa_keygen_bits:$RSA_BITS 2>/dev/null

cat > "$OUT_DIR/ca.cnf" << 'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = NexusC2 Remote Builder CA
O  = NexusC2
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -new -x509 -key "$OUT_DIR/ca.key" -out "$OUT_DIR/ca.crt" \
    -days $DAYS -config "$OUT_DIR/ca.cnf" 2>/dev/null

# --- Server cert (goes on the remote builder machine) ---
echo "[2/3] Generating server certificate..."
openssl genpkey -algorithm RSA -out "$OUT_DIR/server.key" -pkeyopt rsa_keygen_bits:$RSA_BITS 2>/dev/null

# Build SAN list
SAN="DNS.1 = localhost\nIP.1 = 127.0.0.1"
SAN_INDEX=2
DNS_INDEX=2

if [ -n "$REMOTE_HOST" ]; then
    # Detect if it's an IP or a hostname
    if echo "$REMOTE_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        SAN="$SAN\nIP.$SAN_INDEX = $REMOTE_HOST"
        SAN_INDEX=$((SAN_INDEX + 1))
    else
        SAN="$SAN\nDNS.$DNS_INDEX = $REMOTE_HOST"
        DNS_INDEX=$((DNS_INDEX + 1))
    fi
fi

cat > "$OUT_DIR/server.cnf" << EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = nexus-remote-builder
O  = NexusC2
[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
$(echo -e "$SAN")
EOF

openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
    -config "$OUT_DIR/server.cnf" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
    -CAcreateserial -out "$OUT_DIR/server.crt" -days $DAYS \
    -extfile "$OUT_DIR/server.cnf" -extensions v3_req 2>/dev/null

# --- Client cert (goes on the C2 server) ---
echo "[3/3] Generating client certificate..."
openssl genpkey -algorithm RSA -out "$OUT_DIR/client.key" -pkeyopt rsa_keygen_bits:$RSA_BITS 2>/dev/null

cat > "$OUT_DIR/client.cnf" << 'EOF'
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = nexus-c2-server
O  = NexusC2
[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl req -new -key "$OUT_DIR/client.key" -out "$OUT_DIR/client.csr" \
    -config "$OUT_DIR/client.cnf" 2>/dev/null
openssl x509 -req -in "$OUT_DIR/client.csr" -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
    -CAcreateserial -out "$OUT_DIR/client.crt" -days $DAYS \
    -extfile "$OUT_DIR/client.cnf" -extensions v3_req 2>/dev/null

# Cleanup temp files
rm -f "$OUT_DIR"/*.csr "$OUT_DIR"/*.cnf "$OUT_DIR"/*.srl

echo ""
echo "=== Done ==="
echo ""
echo "Files created:"
echo "  $OUT_DIR/ca.crt       — CA certificate (copy to BOTH machines)"
echo "  $OUT_DIR/ca.key       — CA private key (keep safe, offline)"
echo "  $OUT_DIR/server.crt   — Server cert (copy to remote builder)"
echo "  $OUT_DIR/server.key   — Server key  (copy to remote builder)"
echo "  $OUT_DIR/client.crt   — Client cert (stays on C2 server)"
echo "  $OUT_DIR/client.key   — Client key  (stays on C2 server)"
echo ""
echo "Next steps:"
echo "  1. Copy ca.crt, server.crt, server.key to the remote builder machine"
echo "  2. Keep ca.crt, client.crt, client.key on the C2 server"
echo "  3. Update config.toml [builder] section with cert paths and remote address"
echo "  4. See docs/REMOTE-BUILDER.md for full setup instructions"
