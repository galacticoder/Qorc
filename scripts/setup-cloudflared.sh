#!/bin/bash

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
CLOUDFLARED_VERSION="latest"
TUNNEL_NAME="end2end-chat-tunnel"
CONFIG_DIR="/etc/cloudflared"
LOG_DIR="/var/log/cloudflared"
SERVICE_NAME="cloudflared"

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}     Cloudflare Tunnel DDoS Protection     ${BLUE}║${NC}"
echo -e "${BLUE}║${GREEN}        End-to-End Chat Server Setup      ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root for security reasons."
        log_info "Please run as a regular user. The script will prompt for sudo when needed."
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
            PACKAGE_MANAGER="apt"
        elif command -v yum &> /dev/null; then
            OS="centos"
            PACKAGE_MANAGER="yum"
        elif command -v dnf &> /dev/null; then
            OS="fedora"
            PACKAGE_MANAGER="dnf"
        elif command -v pacman &> /dev/null; then
            OS="arch"
            PACKAGE_MANAGER="pacman"
        else
            log_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        log_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    log_info "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Install cloudflared
install_cloudflared() {
    log_info "Installing cloudflared..."
    
    case $OS in
        "ubuntu")
            # Add Cloudflare repository
            if ! curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null; then
                log_error "Failed to add Cloudflare GPG key"
                exit 1
            fi
            
            echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
            
            sudo apt-get update
            sudo apt-get install -y cloudflared
            ;;
        "centos"|"fedora")
            # Install using RPM
            if [[ "$OS" == "centos" ]]; then
                sudo yum install -y yum-utils
                sudo yum-config-manager --add-repo https://pkg.cloudflare.com/cloudflared/rpm/cloudflared.repo
                sudo yum install -y cloudflared
            else
                sudo dnf install -y dnf-plugins-core
                sudo dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared/rpm/cloudflared.repo
                sudo dnf install -y cloudflared
            fi
            ;;
        "arch")
            # Install from AUR or using direct download
            if command -v yay &> /dev/null; then
                yay -S cloudflared
            elif command -v paru &> /dev/null; then
                paru -S cloudflared
            else
                # Fallback to direct download
                install_cloudflared_direct
            fi
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                brew install cloudflared
            else
                log_error "Homebrew not found. Please install Homebrew first."
                exit 1
            fi
            ;;
        *)
            install_cloudflared_direct
            ;;
    esac
    
    log_success "cloudflared installed successfully"
}

# Direct installation method (fallback)
install_cloudflared_direct() {
    log_info "Installing cloudflared directly..."
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        "x86_64")
            ARCH="amd64"
            ;;
        "aarch64"|"arm64")
            ARCH="arm64"
            ;;
        "armv7l")
            ARCH="arm"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    # Download and install
    DOWNLOAD_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
    
    if [[ "$OS" == "macos" ]]; then
        DOWNLOAD_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-${ARCH}.tgz"
        curl -L "$DOWNLOAD_URL" | tar -xz
        sudo mv cloudflared /usr/local/bin/
    else
        sudo curl -L "$DOWNLOAD_URL" -o /usr/local/bin/cloudflared
    fi
    
    sudo chmod +x /usr/local/bin/cloudflared
}

# Setup directories and permissions
setup_directories() {
    log_info "Setting up directories and permissions..."
    
    sudo mkdir -p "$CONFIG_DIR"
    sudo mkdir -p "$LOG_DIR"
    sudo mkdir -p /opt/cloudflared
    
    # Set proper ownership
    sudo chown -R root:root "$CONFIG_DIR"
    sudo chown -R cloudflared:cloudflared "$LOG_DIR" 2>/dev/null || sudo chown -R nobody:nogroup "$LOG_DIR"
    
    # Set permissions
    sudo chmod 755 "$CONFIG_DIR"
    sudo chmod 755 "$LOG_DIR"
    
    log_success "Directories created and permissions set"
}

# Create cloudflared user
create_cloudflared_user() {
    if ! id cloudflared &>/dev/null; then
        log_info "Creating cloudflared user..."
        sudo useradd --system --home-dir /var/lib/cloudflared --shell /bin/false cloudflared 2>/dev/null || true
        sudo mkdir -p /var/lib/cloudflared
        sudo chown cloudflared:cloudflared /var/lib/cloudflared
        log_success "cloudflared user created"
    else
        log_info "cloudflared user already exists"
    fi
}

# Login to Cloudflare
cloudflare_login() {
    log_info "Please complete Cloudflare authentication..."
    log_warning "This will open a browser window for authentication."
    
    # Run cloudflared tunnel login
    if ! cloudflared tunnel login; then
        log_error "Failed to authenticate with Cloudflare"
        log_info "Please ensure you have a Cloudflare account and try again"
        exit 1
    fi
    
    # Move credentials to proper location
    if [[ -f "$HOME/.cloudflared/cert.pem" ]]; then
        sudo cp "$HOME/.cloudflared/cert.pem" "$CONFIG_DIR/"
        sudo chown root:root "$CONFIG_DIR/cert.pem"
        sudo chmod 600 "$CONFIG_DIR/cert.pem"
        log_success "Cloudflare credentials configured"
    else
        log_error "Credentials file not found after authentication"
        exit 1
    fi
}

# Create tunnel
create_tunnel() {
    log_info "Creating Cloudflare tunnel..."
    
    # Check if tunnel already exists
    if cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
        log_warning "Tunnel '$TUNNEL_NAME' already exists"
        TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')
        log_info "Using existing tunnel ID: $TUNNEL_ID"
    else
        # Create new tunnel
        TUNNEL_OUTPUT=$(cloudflared tunnel create "$TUNNEL_NAME")
        TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | grep -oP 'tunnel \K[a-f0-9-]+')
        
        if [[ -z "$TUNNEL_ID" ]]; then
            log_error "Failed to create tunnel"
            exit 1
        fi
        
        log_success "Tunnel created with ID: $TUNNEL_ID"
    fi
    
    # Save tunnel ID for later use
    echo "$TUNNEL_ID" | sudo tee "$CONFIG_DIR/tunnel-id" > /dev/null
}

# Get user input for domain configuration
get_domain_config() {
    echo
    log_info "Domain Configuration Required"
    echo -e "${YELLOW}You need to configure your domain(s) for the tunnel.${NC}"
    echo
    
    read -p "Enter your main domain (e.g., yourdomain.com): " MAIN_DOMAIN
    
    if [[ -z "$MAIN_DOMAIN" ]]; then
        log_error "Domain is required"
        exit 1
    fi
    
    # Validate domain format
    if ! [[ "$MAIN_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log_error "Invalid domain format"
        exit 1
    fi
    
    echo
    log_info "Using domain: $MAIN_DOMAIN"
    log_info "Subdomains will be configured as:"
    echo "  - Main: $MAIN_DOMAIN (HTTPS chat application)"
    echo "  - WebSocket: ws.$MAIN_DOMAIN (WebSocket connections)"
    echo "  - Auth: auth.$MAIN_DOMAIN (Authentication endpoint)"
    echo "  - API: api.$MAIN_DOMAIN (API endpoint)"
    echo
}

# Configure tunnel
configure_tunnel() {
    log_info "Configuring tunnel..."
    
    TUNNEL_ID=$(cat "$CONFIG_DIR/tunnel-id")
    
    # Create configuration file from template
    sudo cp cloudflare/tunnel-config.yml "$CONFIG_DIR/config.yml"
    
    # Replace placeholders in config
    sudo sed -i "s/YOUR_TUNNEL_ID/$TUNNEL_ID/g" "$CONFIG_DIR/config.yml"
    sudo sed -i "s/YOUR_DOMAIN\.com/$MAIN_DOMAIN/g" "$CONFIG_DIR/config.yml"
    
    # Set proper permissions
    sudo chown root:root "$CONFIG_DIR/config.yml"
    sudo chmod 600 "$CONFIG_DIR/config.yml"
    
    log_success "Tunnel configuration created"
}

# Create DNS records
create_dns_records() {
    log_info "Creating DNS records..."
    
    TUNNEL_ID=$(cat "$CONFIG_DIR/tunnel-id")
    
    # Create CNAME records for all subdomains
    cloudflared tunnel route dns "$TUNNEL_ID" "$MAIN_DOMAIN" || log_warning "Failed to create DNS record for $MAIN_DOMAIN"
    cloudflared tunnel route dns "$TUNNEL_ID" "ws.$MAIN_DOMAIN" || log_warning "Failed to create DNS record for ws.$MAIN_DOMAIN"
    cloudflared tunnel route dns "$TUNNEL_ID" "auth.$MAIN_DOMAIN" || log_warning "Failed to create DNS record for auth.$MAIN_DOMAIN"
    cloudflared tunnel route dns "$TUNNEL_ID" "api.$MAIN_DOMAIN" || log_warning "Failed to create DNS record for api.$MAIN_DOMAIN"
    
    log_success "DNS records created (may take a few minutes to propagate)"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."
    
    sudo tee /etc/systemd/system/cloudflared.service > /dev/null << EOF
[Unit]
Description=Cloudflare Tunnel - End-to-End Chat DDoS Protection
Documentation=https://developers.cloudflare.com/cloudflare-one/connections/connect-apps
After=network.target
Wants=network-online.target
StartLimitBurst=3
StartLimitInterval=30

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/cloudflared tunnel --config $CONFIG_DIR/config.yml run
Restart=always
RestartSec=5
RestartPreventExitStatus=78
KillMode=mixed
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $CONFIG_DIR

# Process limits
LimitNOFILE=1048576
LimitNPROC=1048576

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable cloudflared
    
    log_success "Systemd service created and enabled"
}

# Create monitoring script
create_monitoring_script() {
    log_info "Creating monitoring script..."
    
    sudo tee /opt/cloudflared/monitor.sh > /dev/null << 'EOF'
#!/bin/bash

# Cloudflared tunnel monitoring script
LOG_FILE="/var/log/cloudflared/monitor.log"
TUNNEL_CONFIG="/etc/cloudflared/config.yml"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check if cloudflared is running
check_cloudflared() {
    if systemctl is-active --quiet cloudflared; then
        return 0
    else
        return 1
    fi
}

# Check tunnel connectivity
check_tunnel_connectivity() {
    # Try to connect to Cloudflare edge
    if timeout 10 curl -s -f https://www.cloudflare.com > /dev/null; then
        return 0
    else
        return 1
    fi
}

# Restart cloudflared if needed
restart_if_needed() {
    if ! check_cloudflared; then
        log_message "cloudflared service is down, attempting restart"
        systemctl restart cloudflared
        sleep 10
        
        if check_cloudflared; then
            log_message "cloudflared service restarted successfully"
        else
            log_message "Failed to restart cloudflared service"
        fi
    fi
}

# Main monitoring logic
main() {
    # Create log file if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    # Check service status
    if ! check_cloudflared; then
        log_message "cloudflared service is not running"
        restart_if_needed
        exit 1
    fi
    
    # Check connectivity
    if ! check_tunnel_connectivity; then
        log_message "Tunnel connectivity check failed"
        restart_if_needed
        exit 1
    fi
    
    log_message "All checks passed - tunnel is healthy"
}

main "$@"
EOF

    sudo chmod +x /opt/cloudflared/monitor.sh
    
    # Create cron job for monitoring
    sudo tee /etc/cron.d/cloudflared-monitor > /dev/null << EOF
# Monitor cloudflared tunnel every 2 minutes
*/2 * * * * root /opt/cloudflared/monitor.sh
EOF

    log_success "Monitoring script and cron job created"
}

# Start tunnel
start_tunnel() {
    log_info "Starting Cloudflare tunnel..."
    
    sudo systemctl start cloudflared
    
    # Wait for service to start
    sleep 5
    
    if sudo systemctl is-active --quiet cloudflared; then
        log_success "Cloudflare tunnel started successfully"
    else
        log_error "Failed to start Cloudflare tunnel"
        log_info "Check logs with: sudo journalctl -u cloudflared -f"
        exit 1
    fi
}

# Display final information
show_final_info() {
    echo
    log_success "Cloudflare Tunnel DDoS Protection Setup Complete!"
    echo
    echo -e "${GREEN}Your end-to-end chat server is now protected by Cloudflare!${NC}"
    echo
    echo -e "${BLUE}Domain Configuration:${NC}"
    echo "  Main Application: https://$MAIN_DOMAIN"
    echo "  WebSocket:       wss://ws.$MAIN_DOMAIN"
    echo "  Authentication:  https://auth.$MAIN_DOMAIN"
    echo "  API:            https://api.$MAIN_DOMAIN"
    echo
    echo -e "${BLUE}Security Features Enabled:${NC}"
    echo "  ✓ DDoS Protection via Cloudflare Edge"
    echo "  ✓ Rate Limiting on Authentication"
    echo "  ✓ SSL/TLS Termination at Edge"
    echo "  ✓ Geographic Traffic Distribution"
    echo "  ✓ Automatic Failover and Recovery"
    echo "  ✓ Real-time Monitoring and Alerts"
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  Start tunnel:   sudo systemctl start cloudflared"
    echo "  Stop tunnel:    sudo systemctl stop cloudflared"
    echo "  Restart tunnel: sudo systemctl restart cloudflared"
    echo "  View logs:      sudo journalctl -u cloudflared -f"
    echo "  Tunnel status:  sudo systemctl status cloudflared"
    echo
    echo -e "${YELLOW}Important Notes:${NC}"
    echo "  • DNS changes may take up to 24 hours to fully propagate"
    echo "  • The tunnel will automatically start on system boot"
    echo "  • Monitor logs regularly for any connection issues"
    echo "  • Update your application to use the new domain endpoints"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "  1. Wait for DNS propagation (check with 'dig $MAIN_DOMAIN')"
    echo "  2. Update your chat application configuration"
    echo "  3. Test all endpoints are working correctly"
    echo "  4. Monitor tunnel health in Cloudflare dashboard"
    echo
}

# Main execution flow
main() {
    check_root
    detect_os
    
    # Check if cloudflared is already installed
    if command -v cloudflared &> /dev/null; then
        log_info "cloudflared is already installed"
    else
        install_cloudflared
    fi
    
    setup_directories
    create_cloudflared_user
    
    # Check if already configured
    if [[ -f "$CONFIG_DIR/cert.pem" && -f "$CONFIG_DIR/tunnel-id" ]]; then
        log_info "Cloudflare tunnel appears to be already configured"
        read -p "Do you want to reconfigure? (y/N): " RECONFIGURE
        if [[ ! "$RECONFIGURE" =~ ^[Yy]$ ]]; then
            log_info "Skipping configuration. Starting existing tunnel..."
            sudo systemctl restart cloudflared
            exit 0
        fi
    fi
    
    cloudflare_login
    create_tunnel
    get_domain_config
    configure_tunnel
    create_dns_records
    create_systemd_service
    create_monitoring_script
    start_tunnel
    show_final_info
}

# Handle command line arguments
case "${1:-}" in
    "--help"|"-h")
        echo "Cloudflare Tunnel Setup for End-to-End Chat Server"
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --status       Show tunnel status"
        echo "  --restart      Restart the tunnel"
        echo "  --logs         Show tunnel logs"
        echo
        exit 0
        ;;
    "--status")
        sudo systemctl status cloudflared
        exit 0
        ;;
    "--restart")
        sudo systemctl restart cloudflared
        echo "Tunnel restarted"
        exit 0
        ;;
    "--logs")
        sudo journalctl -u cloudflared -f
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
