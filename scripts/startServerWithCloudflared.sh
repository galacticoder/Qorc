#!/bin/bash

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}   End-to-End Chat Server + Cloudflare     ${BLUE}║${NC}"
echo -e "${BLUE}║${GREEN}          DDoS Protection Enabled          ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

# Show help if requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "End-to-End Chat Server with Cloudflare DDoS Protection"
    echo ""
    echo "This script starts the chat server with Cloudflare Tunnel protection."
    echo "All traffic goes through Cloudflare before reaching your server,"
    echo "providing enterprise-grade DDoS protection and performance."
    echo ""
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  --setup-cloudflare  Run Cloudflare tunnel setup"
    echo "  --server-only       Start only the chat server (no tunnel)"
    echo "  --tunnel-only       Start only the Cloudflare tunnel"
    echo "  --status           Show status of all services"
    echo ""
    echo "Environment variables:"
    echo "  CLOUDFLARE_ENABLED     Enable/disable Cloudflare tunnel (default: true)"
    echo "  REDIS_URL             Override Redis connection URL"
    echo "  SKIP_INSTALL          Skip npm dependency installation"
    echo "  DISABLE_CONNECTION_LIMIT  Disable connection limiting"
    echo ""
    exit 0
fi

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Cloudflare tunnel is configured
check_cloudflare_setup() {
    if [[ -f "/etc/cloudflared/config.yml" && -f "/etc/cloudflared/tunnel-id" ]]; then
        return 0
    else
        return 1
    fi
}

# Setup Cloudflare tunnel
setup_cloudflare() {
    log_info "Setting up Cloudflare tunnel for DDoS protection..."
    
    if check_cloudflare_setup; then
        log_info "Cloudflare tunnel is already configured"
        read -p "Do you want to reconfigure it? (y/N): " RECONFIGURE
        if [[ ! "$RECONFIGURE" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    if [[ ! -f "setup-cloudflared.sh" ]]; then
        log_error "setup-cloudflared.sh not found!"
        log_info "Please ensure you have the complete project files."
        exit 1
    fi
    
    log_info "Running Cloudflare tunnel setup..."
    ./setup-cloudflared.sh
}

# Start Cloudflare tunnel
start_cloudflare_tunnel() {
    if ! check_cloudflare_setup; then
        log_warning "Cloudflare tunnel not configured"
        log_info "Run with --setup-cloudflare to configure DDoS protection"
        return 1
    fi
    
    log_info "Starting Cloudflare tunnel..."
    
    if sudo systemctl is-active --quiet cloudflared; then
        log_info "Cloudflare tunnel is already running"
    else
        sudo systemctl start cloudflared
        sleep 3
        
        if sudo systemctl is-active --quiet cloudflared; then
            log_success "Cloudflare tunnel started successfully"
        else
            log_error "Failed to start Cloudflare tunnel"
            log_info "Check logs with: sudo journalctl -u cloudflared -f"
            return 1
        fi
    fi
}

# Check tunnel status
check_tunnel_status() {
    if ! check_cloudflare_setup; then
        echo -e "${YELLOW}Cloudflare Tunnel: Not configured${NC}"
        return 1
    fi
    
    if sudo systemctl is-active --quiet cloudflared; then
        echo -e "${GREEN}Cloudflare Tunnel: Running${NC}"
        
        # Try to get tunnel info
        if command -v cloudflared &> /dev/null; then
            TUNNEL_ID=$(cat /etc/cloudflared/tunnel-id 2>/dev/null || echo "unknown")
            echo -e "${BLUE}Tunnel ID: ${TUNNEL_ID}${NC}"
        fi
        return 0
    else
        echo -e "${RED}Cloudflare Tunnel: Stopped${NC}"
        return 1
    fi
}

# Start Redis (from original startServer.sh)
start_redis() {
    log_info "Starting Redis server..."
    
    if command -v systemctl &> /dev/null; then
        sudo systemctl start redis-server 2>/dev/null || sudo systemctl start redis 2>/dev/null || true
        sudo systemctl enable redis-server 2>/dev/null || sudo systemctl enable redis 2>/dev/null || true
    elif command -v service &> /dev/null; then
        sudo service redis-server start 2>/dev/null || sudo service redis start 2>/dev/null || true
    elif command -v brew &> /dev/null; then
        brew services start redis
    else
        log_warning "Starting Redis manually in background..."
        if command -v redis-server &> /dev/null; then
            redis-server --daemonize yes --bind 127.0.0.1 --port 6379 2>/dev/null || true
        else
            log_warning "Redis server command not found. Please start Redis manually."
        fi
    fi
    
    sleep 3
}

# Check Redis connectivity
check_redis() {
    if command -v redis-cli &> /dev/null; then
        if redis-cli ping &> /dev/null; then
            log_success "Redis is running and accessible"
            return 0
        fi
    fi
    
    log_warning "Redis connectivity check failed"
    return 1
}

# Install dependencies if needed
install_dependencies() {
    if [[ "${SKIP_INSTALL:-false}" == "true" ]]; then
        log_info "Skipping dependency installation (SKIP_INSTALL=true)"
        return 0
    fi
    
    log_info "Checking and installing dependencies..."
    
    # Check if node_modules exists
    if [[ ! -d "node_modules" || ! -d "server/node_modules" ]]; then
        log_info "Installing project dependencies..."
        if command -v pnpm &> /dev/null; then
            pnpm install
        elif command -v npm &> /dev/null; then
            npm install
        else
            log_error "Neither pnpm nor npm found"
            exit 1
        fi
        
        # Install server dependencies
        if [[ -f "server/package.json" ]]; then
            cd server
            npm install
            cd ..
        fi
    fi
}

# Start the chat server
start_chat_server() {
    log_info "Starting End-to-End Chat Server..."
    
    # Set server configuration for tunnel usage
    export CLOUDFLARE_TUNNEL=true
    export TRUST_PROXY=true
    
    # Start the original server
    if [[ -f "startServer.sh" ]]; then
        # Use the original startup script but with tunnel configuration
        SKIP_CLOUDFLARE_CHECK=true ./startServer.sh
    else
        log_error "Original startServer.sh not found!"
        exit 1
    fi
}

# Show status of all services
show_status() {
    echo
    log_info "Service Status Check"
    echo "===================="
    
    # Check Redis
    if check_redis; then
        echo -e "${GREEN}Redis: Running${NC}"
    else
        echo -e "${RED}Redis: Not running${NC}"
    fi
    
    # Check Cloudflare tunnel
    check_tunnel_status
    
    # Check chat server (if running)
    if pgrep -f "node.*server" > /dev/null; then
        echo -e "${GREEN}Chat Server: Running${NC}"
    else
        echo -e "${RED}Chat Server: Not running${NC}"
    fi
    
    echo
}

# Graceful shutdown handler
cleanup() {
    log_info "Shutting down services gracefully..."
    
    # Stop the chat server
    if pgrep -f "node.*server" > /dev/null; then
        log_info "Stopping chat server..."
        pkill -f "node.*server" || true
    fi
    
    log_info "Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Main execution based on arguments
case "${1:-}" in
    "--setup-cloudflare")
        setup_cloudflare
        exit 0
        ;;
    "--server-only")
        log_info "Starting server without Cloudflare tunnel"
        start_redis
        check_redis || exit 1
        install_dependencies
        start_chat_server
        ;;
    "--tunnel-only")
        start_cloudflare_tunnel
        log_info "Cloudflare tunnel started. Chat server not started."
        exit 0
        ;;
    "--status")
        show_status
        exit 0
        ;;
    *)
        # Default: Start everything with DDoS protection
        CLOUDFLARE_ENABLED="${CLOUDFLARE_ENABLED:-true}"
        
        log_info "Starting End-to-End Chat Server with DDoS Protection"
        echo
        
        # Check if Cloudflare is configured
        if [[ "$CLOUDFLARE_ENABLED" == "true" ]]; then
            if ! check_cloudflare_setup; then
                log_warning "Cloudflare tunnel not configured!"
                log_info "For maximum DDoS protection, run: $0 --setup-cloudflare"
                echo
                read -p "Continue without DDoS protection? (y/N): " CONTINUE_WITHOUT
                if [[ ! "$CONTINUE_WITHOUT" =~ ^[Yy]$ ]]; then
                    log_info "Please run: $0 --setup-cloudflare"
                    exit 0
                fi
            else
                # Start Cloudflare tunnel
                start_cloudflare_tunnel || {
                    log_warning "Failed to start Cloudflare tunnel"
                    log_info "Continuing with server startup..."
                }
            fi
        fi
        
        # Start Redis
        start_redis
        check_redis || {
            log_error "Redis is required for the chat server"
            exit 1
        }
        
        # Install dependencies
        install_dependencies
        
        # Show final status
        echo
        show_status
        
        # Start chat server
        log_info "All services ready. Starting chat server..."
        start_chat_server
        ;;
esac
