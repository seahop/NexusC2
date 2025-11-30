#!/bin/bash
# remove-firewall.sh - Remove NexusC2 firewall rules

set -e

echo "Removing NexusC2 firewall rules..."

# Remove the chain from INPUT if present
if iptables -C INPUT -j NEXUSC2_GRPC &>/dev/null; then
    echo "Removing NEXUSC2_GRPC from INPUT chain..."
    iptables -D INPUT -j NEXUSC2_GRPC
fi

# Flush and delete the custom chain
if iptables -L NEXUSC2_GRPC -n &>/dev/null; then
    echo "Flushing NEXUSC2_GRPC chain..."
    iptables -F NEXUSC2_GRPC
    echo "Deleting NEXUSC2_GRPC chain..."
    iptables -X NEXUSC2_GRPC
fi

echo ""
echo "Firewall rules removed successfully!"
echo "gRPC port 50051 is now accessible from all sources."
