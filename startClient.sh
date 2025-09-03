#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat client        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
cd "$(dirname "$0")"

# Create symlinks to package and config files (always ensure they exist)
echo -e "${GREEN}Setting up package and config file symlinks...${NC}"
# Remove existing files/symlinks first
rm -f package.json pnpm-lock.yaml postcss.config.js tailwind.config.ts vite.config.ts tsconfig.json
# Create symlinks to config directory
ln -sf config/package.json package.json
ln -sf config/pnpm-lock.yaml pnpm-lock.yaml
ln -sf config/postcss.config.js postcss.config.js
ln -sf config/tailwind.config.ts tailwind.config.ts
ln -sf config/vite.config.ts vite.config.ts
ln -sf config/tsconfig.json tsconfig.json

# Install deps when needed (first run or lockfile newer than installed modules)
if [ ! -d node_modules ] || [ config/pnpm-lock.yaml -nt node_modules/.modules.yaml ]; then
    if ! command -v pnpm >/dev/null 2>&1; then
        echo -e "${YELLOW}pnpm not found. See https://pnpm.io/installation${NC}"
        exit 1
    fi
    echo -e "${GREEN}Installing client dependencies...${NC}"
    pnpm install --frozen-lockfile --prefer-offline
fi

# Prevent auto-opening external browser and enable Electron DevTools
export BROWSER=none
export ELECTRON_OPEN_DEVTOOLS=1

# Ensure Vite uses fixed port and won't open
export VITE_PORT=5173

# Function to cleanup and retry on module errors
cleanup_and_retry() {
    echo -e "${YELLOW}Module not found error detected. Cleaning up dependencies...${NC}"
    
    # Remove node_modules and lock files
    if [ -d node_modules ]; then
        echo -e "${YELLOW}Removing client node_modules...${NC}"
        rm -rf node_modules
    fi
    
    if [ -f pnpm-lock.yaml ]; then
        echo -e "${YELLOW}Removing client pnpm-lock.yaml...${NC}"
        rm -f pnpm-lock.yaml
    fi
    
    if [ -f package-lock.json ]; then
        echo -e "${YELLOW}Removing client package-lock.json...${NC}"
        rm -f package-lock.json
    fi
    
    echo -e "${GREEN}Reinstalling client dependencies using install script...${NC}"
    
    # Use the install-dependencies.sh script to reinstall client deps
    if [[ -f install-dependencies.sh ]]; then
        echo -e "${GREEN}Found install-dependencies.sh, sourcing and calling main...${NC}"
        # Temporarily disable strict mode to avoid unbound variable errors when sourcing
        set +u
        source install-dependencies.sh
        set -u
        # Call main function to reinstall everything
        main
    else
        # Fallback to manual pnpm install
        echo -e "${YELLOW}install-dependencies.sh not found, using fallback...${NC}"
        # Recreate symlinks
        ln -sf config/pnpm-lock.yaml pnpm-lock.yaml
        pnpm install --frozen-lockfile --prefer-offline
    fi
    
    echo -e "${GREEN}Retrying client startup (final attempt)...${NC}"
    # Restart the client application
    exec "$0" "$@"
}

START_ELECTRON="${START_ELECTRON:-1}"

# Start client with error handling
if [ "$START_ELECTRON" = "1" ]; then
    echo -e "${GREEN}Starting client application (Vite + Electron)...${NC}"
    if ! pnpm run dev 2>&1 | tee /tmp/client_output.log; then
        # Check if the error was module not found and we haven't retried yet
        if grep -q "ERR_MODULE_NOT_FOUND" /tmp/client_output.log && [ ! -f /tmp/client_retry_attempted ]; then
            # Mark that we've attempted a retry
            touch /tmp/client_retry_attempted
            cleanup_and_retry
        else
            # For other errors or if we already retried once, just exit
            rm -f /tmp/client_retry_attempted 2>/dev/null
            exit 1
        fi
    fi &
else
    echo -e "${GREEN}Starting client application (Vite only; no window). Set START_ELECTRON=1 to launch Electron.${NC}"
    if ! pnpm run vite 2>&1 | tee /tmp/client_output.log; then
        # Check if the error was module not found and we haven't retried yet
        if grep -q "ERR_MODULE_NOT_FOUND" /tmp/client_output.log && [ ! -f /tmp/client_retry_attempted ]; then
            # Mark that we've attempted a retry
            touch /tmp/client_retry_attempted
            cleanup_and_retry
        else
            # For other errors or if we already retried once, just exit
            rm -f /tmp/client_retry_attempted 2>/dev/null
            exit 1
        fi
    fi &
fi

CLIENT_PID=$!

cleanup() {
    if [ -n "${CLIENT_PID:-}" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        pkill -P "$CLIENT_PID" 2>/dev/null || true
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    exit
}

trap cleanup INT TERM

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}end2end client is now running!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all processes${NC}"

wait