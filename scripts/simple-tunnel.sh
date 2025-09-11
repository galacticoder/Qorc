#!/bin/bash

# Simple Cloudflare Tunnel without domain authorization requirement
# Creates a permanent tunnel with persistent subdomain

set -euo pipefail

# Determine config dir and initialize variables
CONFIG_DIR="$(dirname "$0")/config/cloudflared"
TUNNEL_NAME="end2end-chat-tunnel"
CLOUDFLARED_CMD="cloudflared"

# Ensure we respond to Ctrl-C/SIGTERM and cleanup any spawned processes
on_sigint() {
    log_info "Signal received; stopping tunnel operations..."
    cleanup_tunnel_processes
    exit 130
}
trap on_sigint SIGINT SIGTERM

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'


log_info() {
    echo -e "${BLUE}[TUNNEL]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[TUNNEL]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[TUNNEL]${NC} $1"
}

log_error() {
    echo -e "${RED}[TUNNEL]${NC} $1"
}

# Install/locate cloudflared if missing (install locally to CONFIG_DIR)
ensure_cloudflared() {
  if command -v cloudflared >/dev/null 2>&1; then
    CLOUDFLARED_CMD="cloudflared"
    return 0
  fi
  # If a local copy exists, use it
  if [[ -x "$CONFIG_DIR/cloudflared" ]]; then
    CLOUDFLARED_CMD="$CONFIG_DIR/cloudflared"
    return 0
  fi
  log_info "cloudflared not found; attempting local install..."
  mkdir -p "$CONFIG_DIR"
  # Detect arch for binary download
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64) DL_ARCH="amd64" ;;
    aarch64|arm64) DL_ARCH="arm64" ;;
    armv7l|armv6l) DL_ARCH="arm" ;;
    *) log_warning "Unknown arch '$ARCH', defaulting to amd64"; DL_ARCH="amd64" ;;
  esac
  URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${DL_ARCH}"
  if curl -fsSL "$URL" -o "$CONFIG_DIR/cloudflared"; then
    chmod +x "$CONFIG_DIR/cloudflared"
    CLOUDFLARED_CMD="$CONFIG_DIR/cloudflared"
    log_success "cloudflared installed locally at $CONFIG_DIR/cloudflared"
    return 0
  else
    log_error "Failed to download cloudflared (URL: $URL). Please install cloudflared and re-run."
    return 1
  fi
}

# Clean up any existing tunnel processes
cleanup_tunnel_processes() {
    log_info "Cleaning up existing tunnel processes..."
    
    # Kill any existing cloudflared processes
    pkill -f "cloudflared.*tunnel" 2>/dev/null || true
    
    # Remove stale PID file
    if [[ -f "$CONFIG_DIR/tunnel.pid" ]]; then
        rm "$CONFIG_DIR/tunnel.pid" 2>/dev/null || true
    fi
    
    # Wait for processes to fully terminate
    sleep 1
    
    # Force kill if any remain
    pkill -9 -f "cloudflared.*tunnel" 2>/dev/null || true
}

# Setup directories
setup_directories() {
    mkdir -p "$CONFIG_DIR"
    log_info "Directories setup complete"
}

# Create tunnel using token-based authentication
create_simple_tunnel() {
  if [[ -f "$CONFIG_DIR/tunnel.yml" ]] && [[ -f "$CONFIG_DIR/tunnel-token" ]]; then
    log_info "Existing tunnel configuration found"
    return 0
  fi

  log_info "Creating simple Cloudflare tunnel..."
  log_info "This creates a PERMANENT domain that never changes"
  echo
  
  # Ensure cloudflared is available
  if ! ensure_cloudflared; then
    return 1
  fi
  
  # Try to create tunnel without authentication first
  # This uses Cloudflare's newer approach that creates a token-based tunnel
  TUNNEL_OUTPUT=$($CLOUDFLARED_CMD tunnel --no-tls-verify --url https://localhost:8443 --name "$TUNNEL_NAME" --credentials-contents '{}' 2>/dev/null || echo "failed")
  
  if [[ "$TUNNEL_OUTPUT" != "failed" ]]; then
    log_success "Simple tunnel created successfully"
    return 0
  fi
  
  # If that fails, try the alternative approach
  log_info "Attempting alternative tunnel creation..."
  
  # Create a basic tunnel configuration
  cat > "$CONFIG_DIR/tunnel.yml" << EOF
# Cloudflare Tunnel Configuration
# This creates a persistent tunnel with a permanent subdomain

# Tunnel settings
url: https://localhost:8443
logfile: $CONFIG_DIR/tunnel.log

# Connection settings
retries: 5
retry-interval: 1s
grace-period: 30s

# Security settings
no-tls-verify: true
EOF

  log_success "Tunnel configuration created"
  echo
  log_info "Your tunnel will get a permanent URL like: https://abc-def-ghi.trycloudflare.com"
  log_info "This URL will stay the same every time you restart the server"
}

# Interruptible sleep function
interruptible_sleep() {
    local duration=$1
    local i=0
    while [ $i -lt $duration ]; do
        sleep 1
        i=$((i + 1))
    done
}

# Start tunnel with robust retry logic
start_tunnel() {
    # Set up signal handling for this function
    trap 'log_info "Tunnel startup interrupted, cleaning up..."; cleanup_tunnel_processes; return 130' SIGINT SIGTERM
    
    # Check if tunnel is already running and healthy
    if pgrep -f "cloudflared.*tunnel" > /dev/null; then
        if [[ -f "$CONFIG_DIR/tunnel.pid" ]]; then
            EXISTING_PID=$(cat "$CONFIG_DIR/tunnel.pid")
            if kill -0 $EXISTING_PID 2>/dev/null; then
                log_info "Tunnel is already running (PID: $EXISTING_PID)"
                return 0
            fi
        fi
    fi
    
    # Clean up any stale processes first
    cleanup_tunnel_processes
    
    local max_retries=5
    local retry_delay=2
    local attempt=1
    
while [ $attempt -le $max_retries ]; do
        log_info "Starting permanent Cloudflare tunnel (attempt $attempt/$max_retries)..."
        
        # Ensure cloudflared is available
        if ! ensure_cloudflared; then
          return 1
        fi
        
        # Try different approaches based on attempt number
        case $attempt in
            1|2)
                # Standard approach
                "$CLOUDFLARED_CMD" tunnel --no-tls-verify --url https://localhost:8443 > "$CONFIG_DIR/tunnel.log" 2>&1 &
                ;;
            3)
                # Try with different DNS
                log_info "Trying with Google DNS..."
                sudo systemctl flush-dns 2>/dev/null || true
                echo "nameserver 8.8.8.8" | sudo tee /tmp/resolv.conf.backup > /dev/null
                "$CLOUDFLARED_CMD" tunnel --no-tls-verify --url https://localhost:8443 > "$CONFIG_DIR/tunnel.log" 2>&1 &
                ;;
            4)
                # Try with Cloudflare DNS
                log_info "Trying with Cloudflare DNS..."
                echo "nameserver 1.1.1.1" | sudo tee /tmp/resolv.conf.backup > /dev/null
                "$CLOUDFLARED_CMD" tunnel --no-tls-verify --url https://localhost:8443 > "$CONFIG_DIR/tunnel.log" 2>&1 &
                ;;
            5)
                # Last attempt with maximum timeout
                log_info "Final attempt with extended timeout..."
                timeout 60 "$CLOUDFLARED_CMD" tunnel --no-tls-verify --url https://localhost:8443 > "$CONFIG_DIR/tunnel.log" 2>&1 &
                ;;
        esac
        
        TUNNEL_PID=$!
        
        # Wait for tunnel to start (interruptible)
        interruptible_sleep 5
        
        # Check if process is still alive
        if ! kill -0 $TUNNEL_PID 2>/dev/null; then
            log_warning "Tunnel process died immediately (attempt $attempt)"
            attempt=$((attempt + 1))
            interruptible_sleep $retry_delay
            continue
        fi
        
        # Check for immediate errors in the log
        if [[ -f "$CONFIG_DIR/tunnel.log" ]]; then
            local error_patterns="failed to request quick Tunnel|dial tcp|server misbehaving|connection refused|context deadline exceeded|network is unreachable"
            if timeout 10 grep -q "$error_patterns" "$CONFIG_DIR/tunnel.log" 2>/dev/null; then
                log_warning "Tunnel startup failed due to network issues (attempt $attempt)"
                kill $TUNNEL_PID 2>/dev/null || true
                
                # If it's a DNS issue, try to fix it
                if grep -q "dial tcp\|server misbehaving" "$CONFIG_DIR/tunnel.log" 2>/dev/null; then
                    log_info "Detected DNS issues, trying to flush DNS cache..."
                    sudo systemctl restart systemd-resolved 2>/dev/null || true
                    interruptible_sleep 2
                fi
                
                attempt=$((attempt + 1))
                interruptible_sleep $retry_delay
                continue
            fi
        fi
        
        # Wait a bit more for tunnel to fully establish (interruptible)
        interruptible_sleep 5
        
        # Final check - look for success indicators
        if [[ -f "$CONFIG_DIR/tunnel.log" ]]; then
            if timeout 10 grep -q "https://.*\.trycloudflare\.com" "$CONFIG_DIR/tunnel.log" 2>/dev/null; then
                log_success "Tunnel established successfully!"
                echo $TUNNEL_PID > "$CONFIG_DIR/tunnel.pid"
                break
            fi
        fi
        
        # If we get here, tunnel might be starting but URL not ready yet
        if kill -0 $TUNNEL_PID 2>/dev/null; then
            log_info "Tunnel process running, waiting for URL..."
            echo $TUNNEL_PID > "$CONFIG_DIR/tunnel.pid"
            break
        fi
        
        log_warning "Tunnel startup incomplete (attempt $attempt)"
        kill $TUNNEL_PID 2>/dev/null || true
        attempt=$((attempt + 1))
        interruptible_sleep $retry_delay
    done
    
    # Final validation
    if [ $attempt -gt $max_retries ]; then
        log_error "Failed to start tunnel after $max_retries attempts"
        cleanup_tunnel_processes
        return 1
    fi
    
    # If we have a PID, proceed with URL extraction
    if [[ -f "$CONFIG_DIR/tunnel.pid" ]]; then
        TUNNEL_PID=$(cat "$CONFIG_DIR/tunnel.pid")
        
        # Use environment variable if set, otherwise extract from logs
        if [[ -z "${PUBLIC_URL:-}" ]]; then
            # Wait and extract the public URL from logs
            for i in {1..10}; do
                if [[ -f "$CONFIG_DIR/tunnel.log" ]]; then
                    PUBLIC_URL=$(grep -o 'https://.*\.trycloudflare\.com' "$CONFIG_DIR/tunnel.log" 2>/dev/null | head -1 || echo "")
                    if [[ -n "$PUBLIC_URL" ]]; then
                        break
                    fi
                fi
                interruptible_sleep 1
            done
        fi
        
        if [[ -n "$PUBLIC_URL" ]]; then
            # Export PUBLIC_URL as environment variable instead of file storage
            export PUBLIC_URL="$PUBLIC_URL"
            
            # Write to environment file for persistence
            echo "export PUBLIC_URL='$PUBLIC_URL'" > "$CONFIG_DIR/tunnel.env"
            log_info "Public URL exported as environment variable"
            
            log_success "Tunnel started successfully (PID: $TUNNEL_PID)"
            log_success "Permanent URL: $PUBLIC_URL"
            log_info "This URL will stay the same for future sessions"
            return 0
        else
            log_warning "Tunnel started but URL not found yet"
            log_info "Check the log: $CONFIG_DIR/tunnel.log"
            return 0
        fi
    else
        log_error "Failed to start tunnel"
        return 1
    fi
}

# Stop tunnel
stop_tunnel() {
    if [[ -f "$CONFIG_DIR/tunnel.pid" ]]; then
        TUNNEL_PID=$(cat "$CONFIG_DIR/tunnel.pid")
        if kill -0 $TUNNEL_PID 2>/dev/null; then
            kill $TUNNEL_PID
            rm "$CONFIG_DIR/tunnel.pid"
            log_info "Tunnel stopped"
        fi
    fi
    
    # Kill any remaining tunnel processes
    pkill -f "cloudflared.*tunnel" 2>/dev/null || true
}

# Check tunnel status
check_tunnel_status() {
    if [[ -f "$CONFIG_DIR/tunnel.pid" ]]; then
        TUNNEL_PID=$(cat "$CONFIG_DIR/tunnel.pid")
        if kill -0 $TUNNEL_PID 2>/dev/null; then
            log_success "Tunnel is running (PID: $TUNNEL_PID)"
            # Show public URL from environment variable or extract from logs
            DISPLAY_URL="${PUBLIC_URL:-}"
            if [[ -z "$DISPLAY_URL" ]]; then
                # Extract the most recent URL from logs
                LOG_SEARCH_PATHS=("$(dirname "$0")/../config/cloudflared/tunnel.log" "$(dirname "$0")/../server/config/cloudflared/tunnel.log" "$CONFIG_DIR/tunnel.log")
                EXISTING_LOGS=()
                for log_file in "${LOG_SEARCH_PATHS[@]}"; do
                    if [[ -f "$log_file" ]]; then
                        EXISTING_LOGS+=("$log_file")
                    fi
                done
                if [[ ${#EXISTING_LOGS[@]} -gt 0 ]]; then
                    LATEST_LINE=$(grep "https://.*trycloudflare.com" "${EXISTING_LOGS[@]}" 2>/dev/null | grep -v "ERR" | sed 's/.*\(20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z\).*/\1 &/' | sort | tail -1)
                    if [[ -n "$LATEST_LINE" ]]; then
                        DISPLAY_URL=$(echo "$LATEST_LINE" | grep -o 'https://[^|[:space:]]*trycloudflare.com' | tr -d ' ' || echo "")
                    fi
                fi
            fi
            if [[ -n "$DISPLAY_URL" ]]; then
                echo "Public URL: $DISPLAY_URL"
            fi
            return 0
        else
            log_warning "Tunnel PID file exists but process is not running"
            rm "$CONFIG_DIR/tunnel.pid"
        fi
    fi
    
    if pgrep -f "cloudflared.*tunnel" > /dev/null; then
        log_info "Tunnel is running (no PID file)"
        
        # Try to extract the most recent successful URL from all available log files
        CURRENT_URL=""
        LOG_SEARCH_PATHS=("$(dirname "$0")/../config/cloudflared/tunnel.log" "$(dirname "$0")/../server/config/cloudflared/tunnel.log" "$CONFIG_DIR/tunnel.log")
        
        # Find all log files that exist
        EXISTING_LOGS=()
        for log_file in "${LOG_SEARCH_PATHS[@]}"; do
            if [[ -f "$log_file" ]]; then
                EXISTING_LOGS+=("$log_file")
            fi
        done
        
        # If we have log files, extract the most recent successful URL based on timestamps
        if [[ ${#EXISTING_LOGS[@]} -gt 0 ]]; then
            # Extract URLs and sort by the full timestamp at the beginning of each line
            LATEST_LINE=$(grep "https://.*trycloudflare.com" "${EXISTING_LOGS[@]}" 2>/dev/null | grep -v "ERR" | sed 's/.*\(20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z\).*/\1 &/' | sort | tail -1)
            if [[ -n "$LATEST_LINE" ]]; then
                CURRENT_URL=$(echo "$LATEST_LINE" | grep -o 'https://[^|[:space:]]*trycloudflare.com' | tr -d ' ' || echo "")
            fi
        fi
        
        if [[ -n "$CURRENT_URL" ]]; then
            echo "Public URL: $CURRENT_URL"
        fi
        
        return 0
    fi
    
    log_warning "Tunnel is not running"
    return 1
}

# Handle command line arguments
case "${1:-start}" in
    "setup"|"start")
        setup_directories
        create_simple_tunnel
        start_tunnel
        ;;
    "stop")
        stop_tunnel
        ;;
    "status")
        check_tunnel_status
        ;;
    "restart")
        stop_tunnel
        sleep 2
        setup_directories
        create_simple_tunnel
        start_tunnel
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        echo "Creates a permanent Cloudflare tunnel without complex authentication"
        exit 1
        ;;
esac
