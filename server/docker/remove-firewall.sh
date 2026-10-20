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

# Remove IPv6 rules if ip6tables is available
if command -v ip6tables &> /dev/null; then
    if ip6tables -C INPUT -p tcp --dport 50051 -j NEXUSC2_GRPC &>/dev/null; then
        echo "Removing IPv6 NEXUSC2_GRPC from INPUT chain..."
        ip6tables -D INPUT -p tcp --dport 50051 -j NEXUSC2_GRPC
    fi

    if ip6tables -L NEXUSC2_GRPC -n &>/dev/null; then
        echo "Flushing IPv6 NEXUSC2_GRPC chain..."
        ip6tables -F NEXUSC2_GRPC
        echo "Deleting IPv6 NEXUSC2_GRPC chain..."
        ip6tables -X NEXUSC2_GRPC
    fi
fi

echo ""
echo "Firewall rules removed successfully!"
echo "gRPC port 50051 is now accessible from all sources."
