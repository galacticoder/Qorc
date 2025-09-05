#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Show help if requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "End-to-End Chat Client Startup Script"
    echo ""
    echo "This script automatically checks and installs dependencies needed"
    echo "to run the end-to-end chat client, including:"
    echo "  • Essential system tools (curl, wget, git)"
    echo "  • Node.js 18+ (JavaScript runtime)"
    echo "  • pnpm (Package manager)"
    echo "  • Electron (Desktop app framework)"
    echo "  • Client dependencies (React, Vite, etc.)"
    echo ""
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo ""
    echo "The script will automatically:"
    echo "  1. Check for essential tools and install if missing"
    echo "  2. Verify Node.js version compatibility"
    echo "  3. Install pnpm if not available"
    echo "  4. Set up configuration symlinks"
    echo "  5. Install client dependencies"
    echo "  6. Start the Electron application"
    echo ""
    exit 0
fi

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat client        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
cd "$(dirname "$0")"

# Function to install essential tools directly
install_essential_tools_direct() {
    echo -e "${YELLOW}Installing essential tools directly...${NC}"

    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        sudo apt-get update
        sudo apt-get install -y curl wget git
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        sudo dnf install -y curl wget git
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        sudo yum install -y curl wget git
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda
        sudo pacman -S --noconfirm curl wget git
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES
        sudo zypper install -y curl wget git
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache curl wget git
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        sudo xbps-install -S curl wget git
    elif command -v emerge &> /dev/null; then
        # Gentoo
        sudo emerge --ask=n net-misc/curl net-misc/wget dev-vcs/git
    elif command -v eopkg &> /dev/null; then
        # Solus
        sudo eopkg install -y curl wget git
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        sudo swupd bundle-add curl wget git
    elif command -v nix-env &> /dev/null; then
        # NixOS
        nix-env -iA nixpkgs.curl nixpkgs.wget nixpkgs.git
    elif command -v brew &> /dev/null; then
        # macOS
        brew install curl wget git
    else
        echo -e "${YELLOW}Could not detect package manager. Please install curl, wget, and git manually.${NC}"
        echo -e "${YELLOW}Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew${NC}"
    fi
}

# Function to check and install essential tools
check_essential_tools() {
    local missing_tools=()

    # Check for essential tools
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    if ! command -v wget &> /dev/null; then
        missing_tools+=("wget")
    fi
    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing essential tools: ${missing_tools[*]}${NC}"
        echo -e "${GREEN}Installing missing tools...${NC}"

        # Try install-dependencies.sh first, then fallback to direct installation
        if [[ -f install-dependencies.sh ]]; then
            set +u
            source install-dependencies.sh
            set -u
            install_system_deps || install_essential_tools_direct
        else
            install_essential_tools_direct
        fi

        # Verify installation
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                echo -e "${YELLOW}Warning: $tool is still not available. Some features may not work.${NC}"
            fi
        done
    fi
}

# Function to check Node.js version
check_nodejs() {
    local nodejs_updated=false

    if ! command -v node &> /dev/null; then
        echo -e "${YELLOW}Node.js not found. Installing via install-dependencies.sh...${NC}"
        if [[ -f install-dependencies.sh ]]; then
            set +u
            source install-dependencies.sh
            set -u
            install_nodejs || true
            nodejs_updated=true
        else
            echo -e "${YELLOW}install-dependencies.sh not found. Please install Node.js manually.${NC}"
            echo -e "${YELLOW}Visit: https://nodejs.org/${NC}"
            exit 1
        fi
    fi

    # Check Node.js version
    local node_version=$(node --version 2>/dev/null | sed 's/v//')
    local major_version=$(echo $node_version | cut -d. -f1)

    if [ "$major_version" -lt 18 ]; then
        echo -e "${YELLOW}Node.js version $node_version is too old. Minimum required: 18.x${NC}"
        echo -e "${GREEN}Updating Node.js via install-dependencies.sh...${NC}"
        if [[ -f install-dependencies.sh ]]; then
            set +u
            source install-dependencies.sh
            set -u
            install_nodejs || true
            nodejs_updated=true
        fi
    fi

    # Only show ready message if Node.js was installed/updated
    if [ "$nodejs_updated" = true ]; then
        echo -e "${GREEN}Node.js $(node --version) is ready.${NC}"
    fi
}

# Check essential tools first
check_essential_tools

# Check Node.js
check_nodejs

# Create symlinks to package and config files (only show message if needed)
setup_symlinks() {
    local needs_setup=false

    # Check if any symlinks are missing or broken
    for file in package.json pnpm-lock.yaml postcss.config.js tailwind.config.ts vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json; do
        if [ ! -L "$file" ] || [ ! -e "$file" ]; then
            needs_setup=true
            break
        fi
    done

    if [ "$needs_setup" = true ]; then
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
    fi
}
setup_symlinks

# Ensure PATH includes common global installation locations
export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.local/share/pnpm:$PATH"

# Check for pnpm first (separate from dependency installation)
if ! command -v pnpm >/dev/null 2>&1; then
        echo -e "${YELLOW}pnpm not found. Installing pnpm...${NC}"

        # Try multiple methods to install pnpm globally
        if command -v corepack &> /dev/null; then
            echo -e "${GREEN}Installing pnpm globally via corepack...${NC}"
            sudo corepack enable pnpm || {
                echo -e "${YELLOW}Corepack failed, trying npm global installation...${NC}"
                if command -v npm &> /dev/null; then
                    sudo npm install -g pnpm --no-audit --no-fund
                else
                    echo -e "${RED}Both corepack and npm failed. Please install pnpm manually.${NC}"
                    exit 1
                fi
            }
        elif command -v npm &> /dev/null; then
            echo -e "${GREEN}Installing pnpm globally via npm...${NC}"
            sudo npm install -g pnpm --no-audit --no-fund
        elif command -v curl &> /dev/null; then
            echo -e "${GREEN}Installing pnpm globally via installer...${NC}"
            # Install to system location
            sudo mkdir -p /usr/local/bin
            curl -fsSL https://github.com/pnpm/pnpm/releases/latest/download/pnpm-linuxstatic-x64 -o /tmp/pnpm
            sudo mv /tmp/pnpm /usr/local/bin/pnpm
            sudo chmod +x /usr/local/bin/pnpm
        else
            echo -e "${RED}No suitable method found to install pnpm. Please install curl or npm first.${NC}"
            exit 1
        fi

        # Update PATH for current session
        export PATH="/usr/local/bin:$HOME/.local/bin:$HOME/.local/share/pnpm:$PATH"

        if ! command -v pnpm >/dev/null 2>&1; then
            echo -e "${YELLOW}pnpm installation failed. Trying manual global installation...${NC}"
            # Try manual binary download as final fallback
            if command -v curl &> /dev/null; then
                sudo mkdir -p /usr/local/bin
                curl -fsSL https://github.com/pnpm/pnpm/releases/latest/download/pnpm-linuxstatic-x64 -o /tmp/pnpm
                sudo mv /tmp/pnpm /usr/local/bin/pnpm
                sudo chmod +x /usr/local/bin/pnpm
            fi
        fi

        if ! command -v pnpm >/dev/null 2>&1; then
            echo -e "${RED}pnpm installation failed. Please install pnpm manually.${NC}"
            echo -e "${YELLOW}Visit: https://pnpm.io/installation${NC}"
            exit 1
        fi

        echo -e "${GREEN}pnpm $(pnpm --version) installed globally.${NC}"
fi

# Install deps when needed (first run or lockfile newer than installed modules)
if [ ! -d node_modules ] || [ config/pnpm-lock.yaml -nt node_modules/.modules.yaml ]; then
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

ensure_electron_installed

# Ensure Electron sandboxing works correctly (Linux fix)
fix_electron_sandbox() {
    local electron_bin
    electron_bin=$(pnpm root)/electron/dist/chrome-sandbox 2>/dev/null
    if [ -f "$electron_bin" ]; then
        # Check if permissions need fixing
        local current_owner=$(stat -c '%U:%G' "$electron_bin" 2>/dev/null || echo "")
        local current_perms=$(stat -c '%a' "$electron_bin" 2>/dev/null || echo "")

        if [ "$current_owner" != "root:root" ] || [ "$current_perms" != "4755" ]; then
            echo -e "${GREEN}Fixing Electron sandbox permissions...${NC}"
            sudo chown root:root "$electron_bin" || true
            sudo chmod 4755 "$electron_bin" || true
        fi
    fi
}
fix_electron_sandbox

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