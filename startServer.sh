#!/bin/bash

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat server        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

# Configure Redis URL (override by exporting REDIS_URL before running this script)
if [ -z "${REDIS_URL:-}" ]; then
    export REDIS_URL="redis://127.0.0.1:6379"
fi
echo -e "${GREEN}Using Redis at: ${REDIS_URL}${NC}"

# Disable global connection limiter by default when using this start script
export DISABLE_CONNECTION_LIMIT="true"
echo -e "${GREEN}Global connection limiter: disabled by start script${NC}"

if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Node.js is not installed. Please install Node.js to run the server.${NC}"
    exit 1
fi

cd server

# Optionally skip dependency step entirely
SKIP_INSTALL="${SKIP_INSTALL:-0}"

if [ "$SKIP_INSTALL" != "1" ]; then
    # Quiet npm output and avoid deprecated transitive audit/fund noise
    export npm_config_audit=false
    export npm_config_fund=false
    export npm_config_progress=false

    if [ -d node_modules ] && [ -f package-lock.json ]; then
        echo -e "${GREEN}Dependencies present; skipping install. Set SKIP_INSTALL=0 and delete node_modules to reinstall.${NC}"
    else
        echo -e "${GREEN}Installing WebSocket server dependencies (prod only)...${NC}"
        if [ -f package-lock.json ]; then
            npm ci --omit=dev
        else
            npm install --omit=dev
        fi
    fi

    # Rebuild native modules to ensure compatibility
    echo -e "${GREEN}Rebuilding native modules...${NC}"
    npm rebuild better-sqlite3
fi

echo -e "${GREEN}Starting secure WebSocket server...${NC}"
node server.js