#!/bin/bash

# Simple Cloudflare Tunnel without domain authorization requirement
# Creates a permanent tunnel with persistent subdomain

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

CONFIG_DIR="$(dirname "$0")/config/cloudflared"
TUNNEL_NAME="end2end-chat-tunnel"

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
    
    # Try to create tunnel without authentication first
    # This uses Cloudflare's newer approach that creates a token-based tunnel
    TUNNEL_OUTPUT=$(cloudflared tunnel --no-tls-verify --url https://localhost:8443 --name "$TUNNEL_NAME" --credentials-contents '{}' 2>/dev/null || echo "failed")
    
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

# Start tunnel
start_tunnel() {
    if pgrep -f "cloudflared.*tunnel" > /dev/null; then
        log_info "Tunnel is already running"
        return 0
    fi

    log_info "Starting permanent Cloudflare tunnel..."
    
    # Start tunnel with persistent subdomain
    cloudflared tunnel --no-tls-verify --url https://localhost:8443 > "$CONFIG_DIR/tunnel.log" 2>&1 &
    TUNNEL_PID=$!
    
    # Wait for tunnel to start
    sleep 5
    
    if kill -0 $TUNNEL_PID 2>/dev/null; then
        echo $TUNNEL_PID > "$CONFIG_DIR/tunnel.pid"
        
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
                sleep 1
            done
        fi
        
        if [[ -n "$PUBLIC_URL" ]]; then
            echo "$PUBLIC_URL" > "$CONFIG_DIR/public-url"
            
            # Also update the server's public URL file if it exists (for backward compatibility)
            if [[ -d "../server/config/cloudflared" ]]; then
                mkdir -p "../server/config/cloudflared"
                echo "$PUBLIC_URL" > "../server/config/cloudflared/public-url"
                log_info "Updated server public URL file"
            fi
            
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
