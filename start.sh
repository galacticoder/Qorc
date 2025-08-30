#!/bin/bash

# Start script for End-to-End Chat Application
cd "$(dirname "$0")"

# Ensure user-local npm bin is on PATH (for pnpm installed to ~/.local)
export PATH="$HOME/.local/bin:$PATH"

# Check if Tor is running
if ! systemctl is-active --quiet tor; then
    echo "Starting Tor service..."
    sudo systemctl start tor
    sleep 3
fi

# Start the application
pnpm run dev
