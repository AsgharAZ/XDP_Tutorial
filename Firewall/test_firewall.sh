#!/bin/bash

# XDP Firewall Test Script
# This script demonstrates the firewall functionality

set -e

INTERFACE=${1:-eth0}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== XDP Firewall Test Script ==="
echo "Interface: $INTERFACE"
echo "Script Directory: $SCRIPT_DIR"
echo

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root for XDP operations"
   exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo
    echo "Cleaning up..."
    if ip link show $INTERFACE | grep -q "xdp"; then
        echo "Removing XDP program from $INTERFACE"
        ip link set dev $INTERFACE xdp off
    fi
    if pgrep -f "flow_manager" > /dev/null; then
        echo "Stopping flow manager"
        pkill -f flow_manager
    fi
    echo "Cleanup complete"
}

# Set trap to cleanup on exit
trap cleanup EXIT

# Build the project
echo "Building firewall components..."
cd "$SCRIPT_DIR"
make clean
make

if [ $? -ne 0 ]; then
    echo "Build failed!"
    exit 1
fi

echo "Build successful!"
echo

# Check if interface exists
if ! ip link show $INTERFACE > /dev/null 2>&1; then
    echo "Interface $INTERFACE not found!"
    echo "Available interfaces:"
    ip link show | grep "^[0-9]" | awk '{print $2}' | tr -d ':'
    exit 1
fi

# Check if interface already has XDP attached
if ip link show $INTERFACE | grep -q "xdp"; then
    echo "XDP program already attached to $INTERFACE. Removing..."
    ip link set dev $INTERFACE xdp off
fi

echo "Starting flow manager in background..."
./flow_manager > flow_manager.log 2>&1 &
FLOW_MANAGER_PID=$!

# Wait a moment for flow manager to start
sleep 2

echo "Attaching XDP firewall to $INTERFACE..."
ip link set dev $INTERFACE xdp obj xdp_prog_kern.o sec xdp

if [ $? -eq 0 ]; then
    echo "XDP program successfully attached to $INTERFACE"
else
    echo "Failed to attach XDP program"
    exit 1
fi

echo
echo "=== Testing Firewall Rules ==="
echo "The firewall is now active. Testing various traffic types..."
echo
echo "Expected behavior:"
echo "- SSH connection attempts should be blocked"
echo "- Non-DNS UDP traffic should be blocked" 
echo "- ICMP echo requests should be blocked"
echo "- DNS queries should be allowed"
echo "- Established connections should be allowed"
echo
echo "Monitoring flow log (press Ctrl+C to stop):"
echo

# Monitor the flow log
tail -f flow_log.txt