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

    # Rebuild native modules only if necessary (or when forced)
    SKIP_REBUILD="${SKIP_REBUILD:-1}"
    if [ "$SKIP_REBUILD" = "0" ]; then
        echo -e "${GREEN}Rebuilding native modules (forced)...${NC}"
        npm rebuild better-sqlite3 || true
    else
        # Verify better-sqlite3 native binding by opening an in-memory DB
        if ! node -e "new (require('better-sqlite3'))(':memory:').close();" >/dev/null 2>&1; then
            echo -e "${GREEN}Rebuilding native modules (auto-detected)...${NC}"
            npm rebuild better-sqlite3 || true
            # Re-test after rebuild; bail if still failing
            if ! node -e "new (require('better-sqlite3'))(':memory:').close();" >/dev/null 2>&1; then
                echo -e "${YELLOW}better-sqlite3 native binding still missing after rebuild.${NC}"
                echo -e "${YELLOW}Try: (1) remove server/node_modules and run npm ci, (2) ensure build tools are installed, (3) set SKIP_REBUILD=0 to force.${NC}"
                exit 1
            fi
        else
            echo -e "${GREEN}Native modules OK; skipping rebuild. Set SKIP_REBUILD=0 to force.${NC}"
        fi
    fi
fi

echo -e "${GREEN}Starting secure WebSocket server...${NC}"

# Auto-detect Postgres and enable backend if DATABASE_URL provided
if [ -n "${DATABASE_URL:-}" ]; then
    export DB_BACKEND=postgres
    echo -e "${GREEN}Database backend: Postgres${NC}"
else
    echo -e "${GREEN}Database backend: SQLite (default)${NC}"
fi

# Optional Redis Cluster
if [ -n "${REDIS_CLUSTER_NODES:-}" ]; then
    echo -e "${GREEN}Using Redis Cluster nodes: ${REDIS_CLUSTER_NODES}${NC}"
fi

# Default to single worker; override with CLUSTER_WORKERS for clustering
export CLUSTER_WORKERS="${CLUSTER_WORKERS:-1}"
echo -e "${GREEN}Cluster workers: ${CLUSTER_WORKERS}${NC}"

# Function to cleanup and retry on module errors
cleanup_and_retry() {
    echo -e "${YELLOW}Module not found error detected. Cleaning up dependencies...${NC}"
    
    # Remove node_modules and lock files
    if [ -d node_modules ]; then
        echo -e "${YELLOW}Removing server/node_modules...${NC}"
        rm -rf node_modules
    fi
    
    if [ -f package-lock.json ]; then
        echo -e "${YELLOW}Removing server/package-lock.json...${NC}"
        rm -f package-lock.json
    fi
    
    if [ -f pnpm-lock.yaml ]; then
        echo -e "${YELLOW}Removing server/pnpm-lock.yaml...${NC}"
        rm -f pnpm-lock.yaml
    fi
    
    echo -e "${GREEN}Reinstalling server dependencies using install script...${NC}"
    # Navigate to project root where install-dependencies.sh is located
    cd ..
    
    echo -e "${GREEN}Working directory: $(pwd)${NC}"
    echo -e "${GREEN}Looking for install-dependencies.sh...${NC}"
    
    # Use the install-dependencies.sh script to reinstall server deps
    if [[ -f install-dependencies.sh ]]; then
        echo -e "${GREEN}Found install-dependencies.sh, sourcing and calling install_server_deps...${NC}"
        # Temporarily disable strict mode to avoid unbound variable errors when sourcing
        set +u
        # Set SERVER_ONLY mode to skip client-side setup (Tor, Electron, etc.)
        export SERVER_ONLY=true
        source install-dependencies.sh
        set -u
        install_server_deps
    else
        # Fallback to manual npm install
        echo -e "${YELLOW}install-dependencies.sh not found at $(pwd), using fallback...${NC}"
        if [[ -d server ]]; then
            echo -e "${GREEN}Found server directory, installing dependencies...${NC}"
            cd server
            npm install --omit=dev
            npm rebuild better-sqlite3 || true
            cd ..
        else
            echo -e "${YELLOW}Server directory not found for fallback install${NC}"
        fi
    fi
    
    echo -e "${GREEN}Retrying server startup (final attempt)...${NC}"
    if [[ -d server ]]; then
        cd server
        exec node server.js
    else
        echo -e "${YELLOW}Server directory not found after cleanup. Cannot restart server.${NC}"
        exit 1
    fi
}

# Start server with error handling
echo -e "${GREEN}Starting secure WebSocket server...${NC}"
if ! node server.js 2>&1 | tee /tmp/server_output.log; then
    # Check if the error was module not found and we haven't retried yet
    if grep -q "ERR_MODULE_NOT_FOUND" /tmp/server_output.log && [ ! -f /tmp/server_retry_attempted ]; then
        # Mark that we've attempted a retry
        touch /tmp/server_retry_attempted
        cleanup_and_retry
    else
        # For other errors or if we already retried once, just exit
        rm -f /tmp/server_retry_attempted 2>/dev/null
        exit 1
    fi
fi