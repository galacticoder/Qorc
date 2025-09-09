#!/bin/bash

set -euo pipefail

# Clean up any leftover temp files from previous runs FIRST
rm -f /tmp/server_startup.stop /tmp/tunnel_monitor.stop /tmp/startup_cleanup.lock /tmp/server_retry_attempted 2>/dev/null || true

# Global stop flags used to coordinate graceful shutdown across background tasks
STOP_FILE="/tmp/server_startup.stop"
MONITOR_STOP_FILE="/tmp/tunnel_monitor.stop"
CLEANUP_LOCK="/tmp/startup_cleanup.lock"
# Session identifier to disambiguate monitors from previous runs
START_SESSION_ID="start_$$_$(date +%s)"

# Cleanup function for proper shutdown
cleanup_on_exit() {
    # Prevent double-execution
    if [[ -f "$CLEANUP_LOCK" ]]; then
        return 0
    fi
    touch "$CLEANUP_LOCK" 2>/dev/null || true
    echo -e "\n[STARTUP] Received shutdown signal, cleaning up..."
    
    # Signal the tunnel monitor to stop before doing anything else to avoid restarts
    echo "[STARTUP] Signaling tunnel monitor to stop..."
    touch "$MONITOR_STOP_FILE" 2>/dev/null || true
    # Signal any ongoing setup to abort cleanly
    touch "$STOP_FILE" 2>/dev/null || true
    
    # Stop tunnel monitoring if it was started (kill this session's monitor first)
    if [[ -f "/tmp/tunnel_monitor.pid.$START_SESSION_ID" ]]; then
        MONITOR_PID=$(cat "/tmp/tunnel_monitor.pid.$START_SESSION_ID" 2>/dev/null || echo "")
        if [[ -n "$MONITOR_PID" ]]; then
            echo "[STARTUP] Stopping tunnel monitor (PID: $MONITOR_PID)..."
            kill -TERM "$MONITOR_PID" 2>/dev/null || true
            # Wait longer for the monitor to exit gracefully
            for i in {1..20}; do
                if kill -0 "$MONITOR_PID" 2>/dev/null; then 
                    sleep 0.5
                else 
                    break
                fi
            done
            # If it's still running, force kill it
            if kill -0 "$MONITOR_PID" 2>/dev/null; then
                echo "[STARTUP] Force killing stubborn tunnel monitor..."
                kill -9 "$MONITOR_PID" 2>/dev/null || true
            fi
        fi
        rm -f "/tmp/tunnel_monitor.pid.$START_SESSION_ID"
    fi
    # Kill any stale monitors from previous sessions
    for pidfile in /tmp/tunnel_monitor.pid.*; do
        if [[ -f "$pidfile" ]]; then
            OLD_PID=$(cat "$pidfile" 2>/dev/null || echo "")
            if [[ -n "$OLD_PID" ]]; then
                echo "[STARTUP] Stopping stale tunnel monitor (PID: $OLD_PID) from $pidfile..."
                kill -TERM "$OLD_PID" 2>/dev/null || true
                sleep 1
                # Force kill if still running
                if kill -0 "$OLD_PID" 2>/dev/null; then
                    kill -9 "$OLD_PID" 2>/dev/null || true
                fi
            fi
            rm -f "$pidfile" 2>/dev/null || true
        fi
    done
    # Backward-compat: old single PID file
    if [[ -f "/tmp/tunnel_monitor.pid" ]]; then
        COMPAT_PID=$(cat /tmp/tunnel_monitor.pid 2>/dev/null || echo "")
        if [[ -n "$COMPAT_PID" ]]; then 
            kill -TERM "$COMPAT_PID" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if kill -0 "$COMPAT_PID" 2>/dev/null; then
                kill -9 "$COMPAT_PID" 2>/dev/null || true
            fi
        fi
        rm -f /tmp/tunnel_monitor.pid
    fi
    
    # Stop tunnel unconditionally using the helper script (path is relative to server/)
    echo "[STARTUP] Stopping Cloudflare tunnel..."
    (cd .. && bash scripts/simple-tunnel.sh stop) 2>/dev/null || true
    
    # Kill any remaining processes
    pkill -f cloudflared 2>/dev/null || true
    pkill -f "node server.js" 2>/dev/null || true
    
    # Clean up temp files
    rm -f "$STOP_FILE" "$MONITOR_STOP_FILE" "$CLEANUP_LOCK" /tmp/server_retry_attempted 2>/dev/null || true
    
    echo "[STARTUP] Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup_on_exit SIGINT SIGTERM SIGQUIT
# Also ensure cleanup runs exactly once on script exit
trap 'cleanup_on_exit' EXIT

# Show help if requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "End-to-End Chat Server Startup Script"
    echo ""
    echo "This script automatically installs and configures all dependencies needed"
    echo "to run the end-to-end chat server, including:"
    echo "  • Essential system tools (curl, wget, gnupg)"
    echo "  • Redis server (for caching and presence)"
    echo "  • Node.js 18+ (JavaScript runtime)"
    echo "  • npm (Node package manager)"
    echo "  • Python3 (for native modules)"
    echo "  • Build tools (gcc, make, etc. - optional)"
    echo ""
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  --no-build        Skip build tools installation prompt"
    echo "  --no-ddos         Skip DDoS protection setup (Cloudflare tunnel)"
    echo "  --ddos-only       Setup DDoS protection and exit"
    echo ""
    echo "Environment variables:"
    echo "  REDIS_URL                Override Redis connection URL"
    echo "  PUBLIC_URL               Set public URL for tunnel (optional)"
    echo "  SKIP_INSTALL             Skip npm dependency installation (true/false)"
    echo "  SKIP_REBUILD             Skip native module rebuild (true/false)"
    echo "  DISABLE_CONNECTION_LIMIT Disable connection limiting (true/false)"
    echo "  ENABLE_DDOS_PROTECTION   Enable DDoS protection (true/false, default: true)"
    echo ""
    exit 0
fi

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}   End2End Chat Server + DDoS Protection   ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

# Parse command line arguments
ENABLE_DDOS_PROTECTION="${ENABLE_DDOS_PROTECTION:-true}"
NO_DDOS=false
DDOS_ONLY=false

for arg in "$@"; do
    case $arg in
        --no-ddos)
            ENABLE_DDOS_PROTECTION="false"
            NO_DDOS=true
            ;;
        --ddos-only)
            DDOS_ONLY=true
            ;;
        --no-build)
            # This is handled elsewhere
            ;;
        --help|-h)
            # This is handled elsewhere
            ;;
    esac
done

# Handle --ddos-only option
if [[ "$DDOS_ONLY" == "true" ]]; then
    echo -e "${BLUE}Setting up DDoS protection only...${NC}"
    setup_ddos_protection() {
        echo -e "${BLUE}Setting up DDoS protection with Cloudflare tunnel...${NC}"
        
        if [[ ! -f "scripts/setup-cloudflared-internal.sh" ]]; then
            echo -e "${RED}DDoS protection script not found!${NC}"
            exit 1
        fi
        
        # Setup cloudflared
        echo -e "${YELLOW}Setting up Cloudflare tunnel...${NC}"
        echo -e "${BLUE}This will open a browser for Cloudflare authentication.${NC}"
        
        if ./scripts/setup-cloudflared-internal.sh setup; then
            echo -e "${GREEN}✓ DDoS protection setup completed!${NC}"
            
            # Start the tunnel
            if ./scripts/setup-cloudflared-internal.sh start; then
                echo -e "${GREEN}✓ DDoS protection tunnel started!${NC}"
                
                if [[ -n "${PUBLIC_URL:-}" ]]; then
                    echo -e "${GREEN}✓ Public URL: ${PUBLIC_URL}${NC}"
                elif [[ -f "config/cloudflared/public-url" ]]; then
                    PUBLIC_URL=$(cat config/cloudflared/public-url)
                    echo -e "${GREEN}✓ Public URL: ${PUBLIC_URL}${NC}"
                fi
                
                echo -e "${BLUE}DDoS protection is now active. Start your server with ./startServer.sh${NC}"
            else
                echo -e "${YELLOW}Setup completed but failed to start tunnel${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Failed to setup DDoS protection${NC}"
            exit 1
        fi
    }
    
    setup_ddos_protection
    exit 0
fi

# Interruptible sleep function for startServer
interruptible_sleep() {
    local duration=$1
    local i=0
    while [ $i -lt $duration ]; do
        sleep 1
        i=$((i + 1))
    done
}

# Function to setup DDoS protection with monitoring
setup_ddos_protection() {
    # If shutdown has begun, abort setup immediately
    if [[ -f "$STOP_FILE" ]]; then
        return 1
    fi
    if [[ "$ENABLE_DDOS_PROTECTION" != "true" ]]; then
        echo -e "${YELLOW}DDoS protection disabled (use --no-ddos to skip this message)${NC}"
        return 0
    fi

    echo -e "${BLUE}Setting up DDoS protection with Cloudflare tunnel...${NC}"
    
    if [[ ! -f "../scripts/simple-tunnel.sh" ]]; then
        echo -e "${YELLOW}DDoS protection script not found. Skipping...${NC}"
        return 0
    fi
    
    # Start the tunnel with robust retry
    echo -e "${GREEN}Starting DDoS protection tunnel (with auto-retry)...${NC}"
    
    local tunnel_attempts=3
    local tunnel_success=false
    
    for attempt in $(seq 1 $tunnel_attempts); do
        # Abort if shutdown was requested
        if [[ -f "$STOP_FILE" ]]; then
            echo -e "${YELLOW}Abort tunnel setup due to shutdown request${NC}"
            return 1
        fi
        echo -e "${BLUE}Tunnel attempt $attempt/$tunnel_attempts...${NC}"
        
        TUNNEL_EXIT_CODE=0
        ../scripts/simple-tunnel.sh start || TUNNEL_EXIT_CODE=$?
        
        if [[ $TUNNEL_EXIT_CODE -eq 130 ]]; then
            echo -e "${YELLOW}Tunnel setup interrupted by user${NC}"
            return 130
        elif [[ $TUNNEL_EXIT_CODE -eq 0 ]]; then
            echo -e "${GREEN}✓ DDoS protection active!${NC}"
            tunnel_success=true
            
            # Show public URL if available
            if [[ -n "${PUBLIC_URL:-}" ]]; then
                echo -e "${GREEN}✓ Public URL: ${PUBLIC_URL}${NC}"
            elif [[ -f "../config/cloudflared/public-url" ]]; then
                PUBLIC_URL=$(cat ../config/cloudflared/public-url)
                echo -e "${GREEN}✓ Public URL: ${PUBLIC_URL}${NC}"
            fi
            break
        else
            echo -e "${YELLOW}Tunnel attempt $attempt failed${NC}"
            if [[ -f "$STOP_FILE" ]]; then
                echo -e "${YELLOW}Abort tunnel setup due to shutdown request${NC}"
                return 1
            fi
            if [[ $attempt -lt $tunnel_attempts ]]; then
                echo -e "${BLUE}Cleaning up and retrying in 5 seconds...${NC}"
                pkill -f cloudflared 2>/dev/null || true
                interruptible_sleep 5
            fi
        fi
    done
    
    if [[ "$tunnel_success" != "true" ]]; then
        echo -e "${YELLOW}Failed to start DDoS protection after $tunnel_attempts attempts.${NC}"
        echo -e "${YELLOW}Server will start without tunnel protection.${NC}"
        # Final cleanup
        pkill -f cloudflared 2>/dev/null || true
        rm -f scripts/config/cloudflared/tunnel.pid 2>/dev/null || true
    fi
    
    return 0
}

# Function to monitor and restart tunnel if needed
monitor_tunnel() {
    # Detach from job control signals to ensure trap in parent can stop us
    trap 'exit 0' SIGINT SIGTERM
    while true; do
        # Check stop conditions more frequently (every 5 seconds instead of 30)
        for i in {1..6}; do
            # Respect stop flag to avoid restarts during shutdown
            if [[ -f "$MONITOR_STOP_FILE" ]]; then
                echo -e "${BLUE}[STARTUP] Tunnel monitor stop flag detected; exiting monitor${NC}"
                rm -f "$MONITOR_STOP_FILE" 2>/dev/null || true
                exit 0
            fi
            
            # If the server process is no longer running, exit the monitor
            if ! pgrep -f "node server.js" >/dev/null 2>&1; then
                echo -e "${BLUE}[STARTUP] Server process not found; exiting tunnel monitor${NC}"
                exit 0
            fi
            
            # If the main startup script is no longer running, exit
            if ! pgrep -f "bash.*startServer.sh" >/dev/null 2>&1; then
                echo -e "${BLUE}[STARTUP] Main startup script not found; exiting tunnel monitor${NC}"
                exit 0
            fi
            
            sleep 5 # Check every 5 seconds
        done
        
        # Only check tunnel status every 30 seconds (after 6 iterations of 5-second sleeps)
        if [[ "$ENABLE_DDOS_PROTECTION" == "true" ]] && [[ -f "../scripts/simple-tunnel.sh" ]]; then
            # Check if tunnel should be running but isn't
            if ! ../scripts/simple-tunnel.sh status >/dev/null 2>&1; then
                # Double-check we should still be running before attempting restart
                if [[ -f "$MONITOR_STOP_FILE" ]] || ! pgrep -f "node server.js" >/dev/null 2>&1; then
                    echo -e "${BLUE}[STARTUP] Stop condition detected during tunnel check; exiting monitor${NC}"
                    exit 0
                fi
                
                echo -e "${YELLOW}[$(date)] Tunnel down, attempting restart...${NC}"
                
                # Try to restart the tunnel
                if timeout 60 ../scripts/simple-tunnel.sh restart >/dev/null 2>&1; then
                    echo -e "${GREEN}[$(date)] Tunnel restarted successfully${NC}"
                else
                    echo -e "${RED}[$(date)] Failed to restart tunnel${NC}"
                fi
            fi
        fi
    done
}

# Function to check DDoS protection status
check_ddos_status() {
    if [[ -f "../scripts/simple-tunnel.sh" ]]; then
        ../scripts/simple-tunnel.sh status
    fi
}

# Function to install essential system tools
install_essential_tools() {
    echo -e "${YELLOW}Installing essential system tools...${NC}"

    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        sudo apt-get update
        sudo apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        sudo dnf install -y curl wget gnupg2 which ca-certificates
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        sudo yum install -y curl wget gnupg2 which ca-certificates
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        # Update package database first
        sudo pacman -Sy --noconfirm
        sudo pacman -S --noconfirm curl wget gnupg which ca-certificates
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        # Refresh repositories first
        sudo zypper refresh
        sudo zypper install -y curl wget gpg2 which ca-certificates
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache curl wget gnupg which bash ca-certificates
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        sudo xbps-install -S curl wget gnupg2 which ca-certificates
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        # Sync portage tree if needed (only if it's very old)
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            sudo emerge --sync --quiet || true
        fi
        sudo emerge --ask=n --quiet net-misc/curl net-misc/wget app-crypt/gnupg sys-apps/which app-misc/ca-certificates
    elif command -v eopkg &> /dev/null; then
        # Solus
        sudo eopkg install -y curl wget gnupg which ca-certificates
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        sudo swupd bundle-add curl wget gnupg which ca-certificates
    elif command -v nix-env &> /dev/null; then
        # NixOS
        nix-env -iA nixpkgs.curl nixpkgs.wget nixpkgs.gnupg nixpkgs.which nixpkgs.cacert
    else
        echo -e "${YELLOW}Could not detect package manager. Please install curl, wget, and gnupg manually.${NC}"
        echo -e "${YELLOW}Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env${NC}"
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
    if ! command -v which &> /dev/null; then
        missing_tools+=("which")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${YELLOW}Missing essential tools: ${missing_tools[*]}${NC}"
        echo -e "${GREEN}Installing missing tools...${NC}"
        install_essential_tools

        # Verify installation
        for tool in "${missing_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                echo -e "${RED}Failed to install $tool. Please install it manually.${NC}"
                exit 1
            fi
        done
        echo -e "${GREEN}Essential tools installed successfully.${NC}"
    else
        echo -e "${GREEN}All essential tools are available.${NC}"
    fi
}

# Function to normalize boolean values (supports both old 0/1 and new true/false formats)
normalize_bool() {
    local value="$1"
    local default="$2"

    # Handle empty/unset values
    if [ -z "${value:-}" ]; then
        echo "$default"
        return
    fi

    # Convert to lowercase for comparison
    value=$(echo "$value" | tr '[:upper:]' '[:lower:]')

    # Handle various true values
    if [[ "$value" == "true" ]] || [[ "$value" == "1" ]] || [[ "$value" == "yes" ]] || [[ "$value" == "on" ]]; then
        echo "true"
    # Handle various false values
    elif [[ "$value" == "false" ]] || [[ "$value" == "0" ]] || [[ "$value" == "no" ]] || [[ "$value" == "off" ]]; then
        echo "false"
    else
        # Invalid value, use default
        echo "$default"
    fi
}

# Function to detect specific distribution details (silent)
detect_distro_details() {
    # This function exists for potential future use but doesn't output anything
    # to keep the script output clean
    return 0
}

# Check if we can use sudo for installations (only warn, don't exit)
if ! sudo -n true 2>/dev/null; then
    echo -e "${YELLOW}Note: You may be prompted for your password to install missing dependencies.${NC}"
    echo ""
fi

# Check and install essential tools first
check_essential_tools

# Detect distribution details
detect_distro_details

# Configure Redis URL (override by exporting REDIS_URL before running this script)
if [ -z "${REDIS_URL:-}" ]; then
    export REDIS_URL="redis://127.0.0.1:6379"
fi
echo -e "${GREEN}Using Redis at: ${REDIS_URL}${NC}"

# Disable global connection limiter by default when using this start script
export DISABLE_CONNECTION_LIMIT="true"
echo -e "${GREEN}Global connection limiter: disabled by start script${NC}"



# Function to check if Redis is running
check_redis() {
    if command -v redis-cli &> /dev/null; then
        if redis-cli ping &> /dev/null; then
            return 0
        fi
    fi
    return 1
}

# Function to install Redis
install_redis() {
    echo -e "${YELLOW}Redis not found. Installing Redis...${NC}"

    # Detect OS and install Redis accordingly
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        echo -e "${GREEN}Installing Redis via apt-get...${NC}"
        sudo apt-get update
        sudo apt-get install -y redis-server
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        echo -e "${GREEN}Installing Redis via dnf...${NC}"
        sudo dnf install -y redis
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        echo -e "${GREEN}Installing Redis via yum...${NC}"
        # Enable EPEL repository for Redis on older systems
        sudo yum install -y epel-release 2>/dev/null || true
        sudo yum install -y redis
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        echo -e "${GREEN}Installing Redis via pacman...${NC}"
        sudo pacman -Sy --noconfirm
        sudo pacman -S --noconfirm redis
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        echo -e "${GREEN}Installing Redis via zypper...${NC}"
        sudo zypper refresh
        # Try different Redis package names for different openSUSE versions
        sudo zypper install -y redis || sudo zypper install -y redis-server
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        echo -e "${GREEN}Installing Redis via apk...${NC}"
        sudo apk add --no-cache redis
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        echo -e "${GREEN}Installing Redis via xbps-install...${NC}"
        sudo xbps-install -S redis
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        echo -e "${GREEN}Installing Redis via emerge...${NC}"
        # Check if we need to sync first
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            sudo emerge --sync --quiet || true
        fi
        # Install with common USE flags for Redis
        sudo emerge --ask=n --quiet dev-db/redis
    elif command -v eopkg &> /dev/null; then
        # Solus
        echo -e "${GREEN}Installing Redis via eopkg...${NC}"
        sudo eopkg install -y redis
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        echo -e "${GREEN}Installing Redis via swupd...${NC}"
        sudo swupd bundle-add redis
    elif command -v nix-env &> /dev/null; then
        # NixOS
        echo -e "${GREEN}Installing Redis via nix-env...${NC}"
        nix-env -iA nixpkgs.redis
    elif command -v brew &> /dev/null; then
        # macOS
        echo -e "${GREEN}Installing Redis via Homebrew...${NC}"
        brew install redis
    else
        echo -e "${RED}Unable to detect package manager. Please install Redis manually.${NC}"
        echo -e "${YELLOW}Visit: https://redis.io/download${NC}"
        echo -e "${YELLOW}Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew${NC}"
        exit 1
    fi
}

# Function to start Redis
start_redis() {
    echo -e "${GREEN}Starting Redis server...${NC}"

    if command -v systemctl &> /dev/null; then
        # systemd systems (most modern Linux distributions)
        sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null || true
        sudo systemctl enable redis-server 2>/dev/null || sudo systemctl enable redis 2>/dev/null || true
    elif command -v service &> /dev/null; then
        # SysV init systems (older distributions)
        sudo service redis-server start 2>/dev/null || sudo service redis start 2>/dev/null || true
    elif command -v rc-service &> /dev/null; then
        # OpenRC (Alpine Linux, Gentoo)
        sudo rc-service redis start 2>/dev/null || true
        sudo rc-update add redis default 2>/dev/null || true
    elif command -v sv &> /dev/null; then
        # runit (Void Linux)
        sudo sv start redis 2>/dev/null || true
        sudo ln -sf /etc/sv/redis /var/service/ 2>/dev/null || true
    elif command -v brew &> /dev/null; then
        # macOS with Homebrew
        brew services start redis
    else
        # Fallback: start Redis manually in background
        echo -e "${YELLOW}Starting Redis manually in background...${NC}"
        if command -v redis-server &> /dev/null; then
            redis-server --daemonize yes --bind 127.0.0.1 --port 6379 2>/dev/null || true
        else
            echo -e "${YELLOW}Redis server command not found. Please start Redis manually.${NC}"
        fi
    fi

    # Wait a moment for Redis to start
    sleep 3
}

# Check and setup Redis
if ! check_redis; then
    echo -e "${YELLOW}Redis is not running or not installed.${NC}"

    # Check if Redis is installed but not running
    if command -v redis-server &> /dev/null; then
        echo -e "${GREEN}Redis is installed but not running. Starting Redis...${NC}"
        start_redis
    else
        # Redis is not installed
        install_redis
        start_redis
    fi

    # Verify Redis is now running
    if ! check_redis; then
        echo -e "${RED}Failed to start Redis. Please check the installation and try again.${NC}"
        echo -e "${YELLOW}You can try starting Redis manually with: redis-server${NC}"
        exit 1
    fi

    echo -e "${GREEN}Redis is now running successfully!${NC}"
else
    echo -e "${GREEN}Redis is already running.${NC}"
fi

# Function to install Node.js
install_nodejs() {
    echo -e "${YELLOW}Node.js not found. Installing Node.js...${NC}"

    # Ensure curl is available for NodeSource installation
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}curl is required for Node.js installation but not found.${NC}"
        exit 1
    fi

    # Detect OS and install Node.js accordingly
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        echo -e "${GREEN}Installing Node.js via NodeSource repository...${NC}"
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        echo -e "${GREEN}Installing Node.js via NodeSource repository...${NC}"
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo dnf install -y nodejs npm
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        echo -e "${GREEN}Installing Node.js via NodeSource repository...${NC}"
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo yum install -y nodejs npm
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        echo -e "${GREEN}Installing Node.js via pacman...${NC}"
        sudo pacman -Sy --noconfirm
        sudo pacman -S --noconfirm nodejs npm
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        echo -e "${GREEN}Installing Node.js via zypper...${NC}"
        sudo zypper refresh
        # Try different Node.js versions - prefer newer versions
        sudo zypper install -y nodejs20 npm20 || \
        sudo zypper install -y nodejs18 npm18 || \
        sudo zypper install -y nodejs npm
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        echo -e "${GREEN}Installing Node.js via apk...${NC}"
        sudo apk add --no-cache nodejs npm
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        echo -e "${GREEN}Installing Node.js via xbps-install...${NC}"
        sudo xbps-install -S nodejs npm
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        echo -e "${GREEN}Installing Node.js via emerge...${NC}"
        # Check if we need to sync first
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            sudo emerge --sync --quiet || true
        fi
        # Install Node.js with npm support
        sudo emerge --ask=n --quiet net-libs/nodejs
    elif command -v eopkg &> /dev/null; then
        # Solus
        echo -e "${GREEN}Installing Node.js via eopkg...${NC}"
        sudo eopkg install -y nodejs npm
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        echo -e "${GREEN}Installing Node.js via swupd...${NC}"
        sudo swupd bundle-add nodejs-basic
    elif command -v nix-env &> /dev/null; then
        # NixOS
        echo -e "${GREEN}Installing Node.js via nix-env...${NC}"
        nix-env -iA nixpkgs.nodejs nixpkgs.nodePackages.npm
    elif command -v brew &> /dev/null; then
        # macOS
        echo -e "${GREEN}Installing Node.js via Homebrew...${NC}"
        brew install node
    else
        echo -e "${RED}Unable to detect package manager for Node.js installation.${NC}"
        echo -e "${YELLOW}Please install Node.js manually from: https://nodejs.org/${NC}"
        echo -e "${YELLOW}Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew${NC}"
        exit 1
    fi
}

# Function to check Node.js version
check_nodejs_version() {
    local node_version=$(node --version 2>/dev/null | sed 's/v//')
    local major_version=$(echo $node_version | cut -d. -f1)

    if [ "$major_version" -lt 18 ]; then
        echo -e "${YELLOW}Node.js version $node_version is too old. Minimum required: 18.x${NC}"
        return 1
    fi
    return 0
}

# Check and setup Node.js
if ! command -v node &> /dev/null; then
    install_nodejs
elif ! check_nodejs_version; then
    echo -e "${YELLOW}Updating Node.js to a newer version...${NC}"
    install_nodejs
fi

# Verify Node.js installation
if ! command -v node &> /dev/null; then
    echo -e "${RED}Failed to install Node.js. Please install it manually.${NC}"
    exit 1
fi

# Verify npm is available
if ! command -v npm &> /dev/null; then
    echo -e "${YELLOW}npm not found. Installing npm...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y npm
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y npm
    elif command -v yum &> /dev/null; then
        sudo yum install -y npm
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm npm
    elif command -v zypper &> /dev/null; then
        sudo zypper install -y npm
    elif command -v apk &> /dev/null; then
        sudo apk add --no-cache npm
    elif command -v xbps-install &> /dev/null; then
        sudo xbps-install -S npm
    elif command -v eopkg &> /dev/null; then
        sudo eopkg install -y npm
    else
        echo -e "${RED}Failed to install npm. Please install it manually.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}Node.js $(node --version) and npm $(npm --version) are ready.${NC}"

# Function to install build tools for native modules
install_build_tools() {
    echo -e "${YELLOW}Installing build tools for native modules...${NC}"

    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        sudo apt-get update
        sudo apt-get install -y build-essential python3 python3-dev make g++ libc6-dev
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        sudo dnf groupinstall -y "Development Tools" || sudo dnf group install -y "Development Tools"
        sudo dnf install -y python3 python3-devel make gcc-c++ glibc-devel
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        sudo yum groupinstall -y "Development Tools"
        sudo yum install -y python3 python3-devel make gcc-c++ glibc-devel
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        sudo pacman -Sy --noconfirm
        # base-devel includes make, gcc, binutils, etc.
        sudo pacman -S --noconfirm base-devel python python-pip
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        sudo zypper refresh
        # Try to install development pattern first, fallback to individual packages
        sudo zypper install -y -t pattern devel_basis devel_C_C++ || \
        sudo zypper install -y gcc gcc-c++ make binutils glibc-devel
        sudo zypper install -y python3 python3-devel python3-pip
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache build-base python3 python3-dev make g++ libc-dev
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        sudo xbps-install -S base-devel python3 python3-devel make gcc
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        # Check if we need to sync first
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            sudo emerge --sync --quiet || true
        fi
        # Install essential build tools
        sudo emerge --ask=n --quiet sys-devel/gcc sys-devel/make sys-devel/binutils \
            dev-lang/python dev-python/pip sys-libs/glibc
    elif command -v eopkg &> /dev/null; then
        # Solus
        sudo eopkg install -y -c system.devel python3 python3-devel make gcc
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        sudo swupd bundle-add c-basic python3-basic devpkg-glibc
    elif command -v nix-env &> /dev/null; then
        # NixOS
        nix-env -iA nixpkgs.gcc nixpkgs.gnumake nixpkgs.python3 nixpkgs.glibc
    elif command -v brew &> /dev/null; then
        # macOS - Xcode command line tools
        if ! xcode-select -p &> /dev/null; then
            echo -e "${GREEN}Installing Xcode command line tools...${NC}"
            xcode-select --install
            echo -e "${YELLOW}Please complete the Xcode command line tools installation and run this script again.${NC}"
            exit 1
        fi
        # Install Python if not available
        if ! command -v python3 &> /dev/null; then
            brew install python
        fi
    else
        echo -e "${YELLOW}Could not install build tools automatically. You may need to install them manually if native modules fail to build.${NC}"
        echo -e "${YELLOW}Required: build tools (gcc/clang), make, python3, development headers${NC}"
        echo -e "${YELLOW}Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew${NC}"
    fi
}

# Function to check for Python3
check_python3() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${YELLOW}Python3 not found. Installing Python3...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y python3 python3-dev
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3 python3-devel
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-devel
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm python
        elif command -v zypper &> /dev/null; then
            sudo zypper install -y python3 python3-devel
        elif command -v apk &> /dev/null; then
            sudo apk add --no-cache python3 python3-dev
        elif command -v xbps-install &> /dev/null; then
            sudo xbps-install -S python3 python3-devel
        elif command -v emerge &> /dev/null; then
            sudo emerge --ask=n dev-lang/python
        elif command -v eopkg &> /dev/null; then
            sudo eopkg install -y python3 python3-devel
        elif command -v swupd &> /dev/null; then
            sudo swupd bundle-add python3-basic
        elif command -v nix-env &> /dev/null; then
            nix-env -iA nixpkgs.python3
        elif command -v brew &> /dev/null; then
            brew install python
        else
            echo -e "${YELLOW}Could not install Python3 automatically. Please install it manually.${NC}"
        fi
    fi
}

# Check for Python3 (required for native modules)
check_python3

# Check if build tools are needed and available
if [[ "${1:-}" != "--no-build" ]] && (! command -v make &> /dev/null || ! command -v gcc &> /dev/null); then
    echo -e "${YELLOW}Build tools not found. These may be needed for native modules.${NC}"
    read -p "Install build tools? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_build_tools
    else
        echo -e "${YELLOW}Skipping build tools installation. Native modules may fail to build.${NC}"
    fi
elif [[ "${1:-}" == "--no-build" ]]; then
    echo -e "${YELLOW}Skipping build tools check (--no-build specified).${NC}"
fi

cd server

# Optionally skip dependency step entirely
SKIP_INSTALL=$(normalize_bool "${SKIP_INSTALL:-}" "false")

if [ "$SKIP_INSTALL" != "true" ]; then
    # Quiet npm output and avoid deprecated transitive audit/fund noise
    export npm_config_audit=false
    export npm_config_fund=false
    export npm_config_progress=false

    if [ -d node_modules ] && [ -f package-lock.json ]; then
        echo -e "${GREEN}Dependencies present; skipping install. Set SKIP_INSTALL=false and delete node_modules to reinstall.${NC}"
    else
        echo -e "${GREEN}Installing WebSocket server dependencies (prod only)...${NC}"
        if [ -f package-lock.json ]; then
            npm ci --omit=dev
        else
            npm install --omit=dev
        fi
    fi

    # Rebuild native modules only if necessary (or when forced)
    SKIP_REBUILD=$(normalize_bool "${SKIP_REBUILD:-}" "true")
    if [ "$SKIP_REBUILD" = "false" ]; then
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
                echo -e "${YELLOW}Try: (1) remove server/node_modules and run npm ci, (2) ensure build tools are installed, (3) set SKIP_REBUILD=false to force.${NC}"
                exit 1
            fi
        else
            echo -e "${GREEN}Native modules OK; skipping rebuild. Set SKIP_REBUILD=false to force.${NC}"
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

# Setup DDoS protection before starting server
DDOS_EXIT_CODE=0
setup_ddos_protection || DDOS_EXIT_CODE=$?

# Handle interrupt during tunnel setup
if [[ $DDOS_EXIT_CODE -eq 130 ]]; then
    echo -e "${YELLOW}Server startup interrupted during tunnel setup${NC}"
    cleanup_on_exit
    exit 130
fi

# Show final status
echo
echo -e "${BLUE}=== Server Status ===${NC}"
echo -e "${GREEN}✓ Redis: Running${NC}"
if [[ "$ENABLE_DDOS_PROTECTION" == "true" ]]; then
    check_ddos_status
fi
echo

# Start tunnel monitoring in background if tunnel is enabled
if [[ "$ENABLE_DDOS_PROTECTION" == "true" ]] && [[ -f "../scripts/simple-tunnel.sh" ]]; then
    echo -e "${BLUE}Starting tunnel monitoring service...${NC}"
    monitor_tunnel &
    MONITOR_PID=$!
    echo "$MONITOR_PID" > "/tmp/tunnel_monitor.pid.$START_SESSION_ID"
    # Backward-compat single PID file for older cleanups
    echo "$MONITOR_PID" > /tmp/tunnel_monitor.pid
fi

# Start server with error handling
echo -e "${GREEN}Starting secure WebSocket server...${NC}"

# Ensure cleanup happens on script exit
trap 'cleanup_on_exit' EXIT

# Start the server
if ! node server.js 2>&1 | tee /tmp/server_output.log; then
    # Check if the error was module not found and we haven't retried yet
    if grep -q "ERR_MODULE_NOT_FOUND" /tmp/server_output.log && [ ! -f /tmp/server_retry_attempted ]; then
        # Mark that we've attempted a retry
        touch /tmp/server_retry_attempted
        cleanup_and_retry
    else
        # For other errors or if we already retried once, just exit
        rm -f /tmp/server_retry_attempted 2>/dev/null
        cleanup_on_exit
        exit 1
    fi
fi

# If we get here, server exited normally
cleanup_on_exit
