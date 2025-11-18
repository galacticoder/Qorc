#!/bin/bash
# Cluster CLI Wrapper Script
# Usage: ./cluster-cli.sh [command] [args...]

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/server"

# Check if we're in the right directory
if [ ! -f "$SERVER_DIR/package.json" ]; then
    echo "Error: Cannot find server/package.json"
    exit 1
fi

# Check if node_modules exists
if [ ! -d "$SERVER_DIR/node_modules" ]; then
    echo "Installing server dependencies..."
    cd "$SERVER_DIR"
    npm install
    cd "$SCRIPT_DIR"
fi

# Check if CLUSTER_ADMIN_TOKEN is set
if [ -z "$CLUSTER_ADMIN_TOKEN" ]; then
    echo "Error: CLUSTER_ADMIN_TOKEN environment variable not set"
    echo ""
    echo "Please set it first:"
    echo "  export CLUSTER_ADMIN_TOKEN='your-admin-token-here'"
    echo ""
    echo "Or run with the variable:"
    echo "  CLUSTER_ADMIN_TOKEN='your-token' ./cluster-cli.sh status"
    exit 1
fi

# Run the cluster CLI from the server directory
cd "$SERVER_DIR"
node cluster/cluster-cli.js "$@"