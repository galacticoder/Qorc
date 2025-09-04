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
rm -f package.json pnpm-lock.yaml postcss.config.js tailwind.config.ts vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json
# Create symlinks to config directory
ln -sf config/package.json package.json
ln -sf config/pnpm-lock.yaml pnpm-lock.yaml
ln -sf config/postcss.config.js postcss.config.js
ln -sf config/tailwind.config.ts tailwind.config.ts
ln -sf config/vite.config.ts vite.config.ts
ln -sf config/tsconfig.json tsconfig.json
ln -sf config/tsconfig.app.json tsconfig.app.json
ln -sf config/tsconfig.node.json tsconfig.node.json

# Install deps when needed (first run or lockfile newer than installed modules)
if [ ! -d node_modules ] || [ config/pnpm-lock.yaml -nt node_modules/.modules.yaml ]; then
    if ! command -v pnpm >/dev/null 2>&1; then
        echo -e "${YELLOW}pnpm not found. Attempting to install prerequisites...${NC}"
        if [[ -f install-dependencies.sh ]]; then
            set +u
            source install-dependencies.sh
            set -u
            install_nodejs || true
            install_pnpm || true
            export PATH="$HOME/.local/bin:$PATH"
        fi
        if ! command -v pnpm >/dev/null 2>&1; then
            echo -e "${YELLOW}pnpm still not found. See https://pnpm.io/installation${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}Installing client dependencies...${NC}"
    pnpm install --prefer-offline
fi

# Ensure critical dev dependencies are present (no sleeps; install immediately if missing)
ensure_deps() {
    local missing=0
    for pkg in "@tailwindcss/aspect-ratio" tailwindcss autoprefixer "@vitejs/plugin-react" vite electron concurrently wait-on typescript socks-proxy-agent; do
        node -e "require.resolve('${pkg}')" >/dev/null 2>&1 || missing=1
    done
    if [ "$missing" -eq 1 ]; then
        echo -e "${YELLOW}Detected missing dev dependencies. Installing now...${NC}"
        pnpm install
    fi
}
ensure_deps

# Ensure Electron binary is fetched correctly
ensure_electron_installed() {
    if ! node -e "require('electron')" >/dev/null 2>&1; then
        echo -e "${YELLOW}Electron not fully installed. Attempting to fetch platform binary...${NC}"
        local install_js
        install_js=$(node -e "try{console.log(require.resolve('electron/install.js'))}catch(e){process.exit(1)}") || true
        if [ -n "$install_js" ] && [ -f "$install_js" ]; then
            echo -e "${GREEN}Running Electron install script: $install_js${NC}"
            node "$install_js" || true
        fi
    fi
    # Re-check and fail clearly if still not available
    if ! node -e "require('electron')" >/dev/null 2>&1; then
        echo -e "${YELLOW}Electron still not available; reinstalling electron package...${NC}"
        pnpm add -D electron@latest
        # Run install script again
        local install_js2
        install_js2=$(node -e "try{console.log(require.resolve('electron/install.js'))}catch(e){process.exit(1)}") || true
        if [ -n "$install_js2" ] && [ -f "$install_js2" ]; then
            node "$install_js2" || true
        fi
    fi
}

# Ensure server dependencies are installed (needed for Tor verification)
ensure_server_deps() {
    if [ -d "server" ]; then
        echo -e "${GREEN}Checking server dependencies...${NC}"
        cd server
        
        # Check if socks-proxy-agent is available in server
        if ! node -e "require.resolve('socks-proxy-agent')" >/dev/null 2>&1; then
            echo -e "${YELLOW}Installing server dependencies including socks-proxy-agent...${NC}"
            # Use pnpm if available, otherwise fall back to npm
            if command -v pnpm >/dev/null 2>&1; then
                pnpm install
            else
                npm install
            fi
        fi
        
        cd ..
    fi
}
ensure_electron_installed

# Ensure Electron sandboxing works correctly (Linux fix)
fix_electron_sandbox() {
    local electron_bin
    electron_bin=$(pnpm root)/electron/dist/chrome-sandbox
    if [ -f "$electron_bin" ]; then
        echo -e "${GREEN}Fixing Electron sandbox permissions...${NC}"
        sudo chown root:root "$electron_bin" || true
        sudo chmod 4755 "$electron_bin" || true
    fi
}
fix_electron_sandbox

ensure_server_deps

# Prevent auto-opening external browser and enable Electron DevTools
export BROWSER=none
export ELECTRON_OPEN_DEVTOOLS=1
export ELECTRON_DISABLE_SECURITY_WARNINGS=1

# Ensure Vite uses fixed port and won't open
export VITE_PORT=5173

# Ensure a TCP port is free by killing any process bound to it (best-effort)
ensure_port_free() {
    local port="$1"
    echo -e "${GREEN}Ensuring port ${port} is free...${NC}"
    # Try lsof
    if command -v lsof >/dev/null 2>&1; then
        local pids
        pids=$(lsof -t -i TCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)
        if [ -n "$pids" ]; then
            echo "$pids" | xargs -r kill -9 2>/dev/null || true
        fi
    fi
    # Try fuser
    if command -v fuser >/dev/null 2>&1; then
        fuser -k "${port}/tcp" 2>/dev/null || true
    fi
    # Try ss (Linux)
    if command -v ss >/dev/null 2>&1; then
        local spids
        spids=$(ss -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p {print $NF}' | sed -E 's/.*pid=([0-9]+).*/\1/' | sort -u)
        if [ -n "$spids" ]; then
            echo "$spids" | xargs -r kill -9 2>/dev/null || true
        fi
    fi
}

# Free vite dev port if occupied
ensure_port_free "$VITE_PORT"

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
    
    echo -e "${GREEN}Reinstalling client dependencies (online)...${NC}"
    # Recreate symlinked lockfile if present in config
    if [ -f config/pnpm-lock.yaml ]; then
        ln -sf config/pnpm-lock.yaml pnpm-lock.yaml
    fi
    pnpm install
    ensure_deps
    ensure_electron_installed
    
    echo -e "${GREEN}Retrying client startup (final attempt)...${NC}"
    # Restart the client application using absolute script path
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    exec /usr/bin/bash "$SCRIPT_DIR/startClient.sh" "$@"
}

START_ELECTRON="${START_ELECTRON:-1}"

# Start client with error handling
if [ "$START_ELECTRON" = "1" ]; then
    echo -e "${GREEN}Starting client application (Vite + Electron)...${NC}"
    # Start Vite in background
    pnpm exec vite &
    VITE_PID=$!
    
    # Ensure cleanup kills Vite on exit
    CLIENT_PID=$VITE_PID
    
    # Wait for dev server to be ready without sleeps
    if ! pnpm exec wait-on "http://localhost:${VITE_PORT}"; then
        echo -e "${YELLOW}Dev server failed to start${NC}"
        kill "$VITE_PID" 2>/dev/null || true
        wait "$VITE_PID" 2>/dev/null || true
        if [ ! -f /tmp/client_retry_attempted ]; then
            touch /tmp/client_retry_attempted
            cleanup_and_retry
        else
            rm -f /tmp/client_retry_attempted 2>/dev/null
            exit 1
        fi
    fi

    # Launch Electron in foreground; when it exits, stop Vite and exit with same code
    NODE_ENV=development pnpm exec electron .
    EC=$?
    kill "$VITE_PID" 2>/dev/null || true
    wait "$VITE_PID" 2>/dev/null || true
    rm -f /tmp/client_retry_attempted 2>/dev/null || true
    exit $EC
else
    echo -e "${GREEN}Starting client application (Vite only; no window). Set START_ELECTRON=1 to launch Electron.${NC}"
    if ! pnpm run vite 2>&1 | tee /tmp/client_output.log; then
        # Check if the error was module not found and we haven't retried yet
        if (grep -q "ERR_MODULE_NOT_FOUND" /tmp/client_output.log || \
            grep -q "MODULE_NOT_FOUND" /tmp/client_output.log || \
            grep -q "Cannot find module" /tmp/client_output.log || \
            grep -q "Cannot find package" /tmp/client_output.log) && [ ! -f /tmp/client_retry_attempted ]; then
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