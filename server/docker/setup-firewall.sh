#!/bin/bash
# setup-firewall.sh - Configure iptables rules for NexusC2 security
# This script blocks external access to the gRPC port while allowing internal Docker communication

set -e

echo "Setting up firewall rules for NexusC2..."

# Get the Docker bridge network subnet (172.28.0.0/16)
DOCKER_SUBNET="172.28.0.0/16"
GRPC_PORT="50051"

# Create a custom chain for NexusC2 rules
if ! iptables -L NEXUSC2_GRPC -n &>/dev/null; then
    echo "Creating NEXUSC2_GRPC chain..."
    iptables -N NEXUSC2_GRPC
fi

# Flush existing rules in the chain
echo "Flushing existing rules..."
iptables -F NEXUSC2_GRPC

# Allow localhost connections to gRPC (for agent-handler itself)
echo "Allowing localhost connections to port $GRPC_PORT..."
iptables -A NEXUSC2_GRPC -s 127.0.0.1 -p tcp --dport $GRPC_PORT -j ACCEPT

# Try to add IPv6 localhost rule if ip6tables is available
if command -v ip6tables &> /dev/null; then
    echo "Adding IPv6 localhost rule..."
    ip6tables -A NEXUSC2_GRPC -s ::1 -p tcp --dport $GRPC_PORT -j ACCEPT 2>/dev/null || echo "  (IPv6 rule skipped - not available)"
fi

# Allow connections from Docker bridge network (containers)
echo "Allowing Docker network ($DOCKER_SUBNET) connections to port $GRPC_PORT..."
iptables -A NEXUSC2_GRPC -s $DOCKER_SUBNET -p tcp --dport $GRPC_PORT -j ACCEPT

# Drop all other connections to gRPC port
echo "Blocking external connections to port $GRPC_PORT..."
iptables -A NEXUSC2_GRPC -p tcp --dport $GRPC_PORT -j DROP

# Insert the chain into INPUT if not already present
if ! iptables -C INPUT -j NEXUSC2_GRPC &>/dev/null; then
    echo "Adding NEXUSC2_GRPC chain to INPUT..."
    iptables -I INPUT 1 -j NEXUSC2_GRPC
fi

echo ""
echo "Firewall rules applied successfully!"
echo ""
echo "Current NEXUSC2_GRPC rules:"
iptables -L NEXUSC2_GRPC -n -v --line-numbers
echo ""
echo "Port $GRPC_PORT is now:"
echo "  ✓ Accessible from localhost (127.0.0.1)"
echo "  ✓ Accessible from Docker containers ($DOCKER_SUBNET)"
echo "  ✗ Blocked from external networks"
echo ""
echo "To remove these rules, run: ./remove-firewall.sh"
