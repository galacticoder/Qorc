#!/bin/bash

# End-to-End Chat Site - System Dependencies Installer
# This script installs all necessary system dependencies for the secure chat application

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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
        log_error "This script should not be run as root. Please run as a regular user."
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS. This script supports Ubuntu/Debian, Fedora/RHEL, and Arch Linux."
        exit 1
    fi
    
    log_info "Detected OS: $OS $OS_VERSION"
}

# Update package manager
update_packages() {
    log_info "Updating package manager..."
    
    case $OS in
        ubuntu|debian)
            sudo apt update
            ;;
        fedora|rhel|centos)
            sudo dnf update -y
            ;;
        arch|manjaro)
            sudo pacman -Sy
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log_success "Package manager updated"
}

# Install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            sudo apt install -y \
                curl \
                wget \
                git \
                build-essential \
                python3 \
                python3-pip \
                tor \
                torsocks \
                obfs4proxy \
                ca-certificates \
                gnupg \
                lsb-release \
                software-properties-common \
                apt-transport-https
            ;;
        fedora|rhel|centos)
            sudo dnf install -y \
                curl \
                wget \
                git \
                gcc \
                gcc-c++ \
                make \
                python3 \
                python3-pip \
                tor \
                torsocks \
                obfs4 \
                ca-certificates \
                gnupg2
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm \
                curl \
                wget \
                git \
                base-devel \
                python \
                python-pip \
                tor \
                torsocks \
                obfs4proxy \
                ca-certificates \
                gnupg
            ;;
    esac
    
    log_success "System dependencies installed"
}

# Install Node.js and npm
install_nodejs() {
    log_info "Installing Node.js and npm..."
    
    # Check if Node.js is already installed
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        log_info "Node.js is already installed: $NODE_VERSION"
        
        # Check if version is >= 18
        MAJOR_VERSION=$(echo $NODE_VERSION | cut -d'.' -f1 | sed 's/v//')
        if [[ $MAJOR_VERSION -ge 18 ]]; then
            log_success "Node.js version is compatible"
            return
        else
            log_warning "Node.js version is too old. Installing newer version..."
        fi
    fi
    
    # Install Node.js via NodeSource repository
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    
    case $OS in
        ubuntu|debian)
            sudo apt install -y nodejs
            ;;
        fedora|rhel|centos)
            sudo dnf install -y nodejs npm
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm nodejs npm
            ;;
    esac
    
    log_success "Node.js and npm installed"
    node --version
    npm --version
}

# Install pnpm
install_pnpm() {
    log_info "Installing pnpm package manager..."

    if command -v pnpm &> /dev/null; then
        log_info "pnpm is already installed: $(pnpm --version)"
        return
    fi

    # Determine desired pnpm version from package.json if specified
    PNPM_VER=""
    if [[ -f package.json ]]; then
        PKG_MGR=$(grep -oE '"packageManager"\s*:\s*"[^"]+"' package.json | sed -E 's/.*"packageManager"\s*:\s*"([^"]+)".*/\1/')
        if [[ $PKG_MGR == pnpm@* ]]; then
            PNPM_VER="${PKG_MGR#pnpm@}"
        fi
    fi
    if [[ -z "$PNPM_VER" ]]; then
        PNPM_VER="8"  # default to pnpm v8 if not specified
    fi

    # Install pnpm to user directory to avoid requiring sudo
    NPM_PREFIX="$HOME/.local"
    mkdir -p "$NPM_PREFIX"
    log_info "Installing pnpm@$PNPM_VER to $NPM_PREFIX (user scope)"
    npm install -g "pnpm@${PNPM_VER}" --prefix "$NPM_PREFIX"

    # Ensure user's local bin is on PATH for current script and future shells
    export PATH="$HOME/.local/bin:$PATH"
    SHELL_RC=""
    if [[ -n "$ZSH_VERSION" ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -n "$BASH_VERSION" ]]; then
        SHELL_RC="$HOME/.bashrc"
    else
        SHELL_RC="$HOME/.profile"
    fi
    if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
    fi

    if command -v pnpm &> /dev/null; then
        log_success "pnpm installed: $(pnpm --version)"
    else
        log_error "pnpm did not install correctly. Check npm configuration and PATH."
        exit 1
    fi
}

# Configure Tor
configure_tor() {
    log_info "Configuring Tor..."

    # Create Tor configuration directory if it doesn't exist
    sudo mkdir -p /etc/tor

    # Backup existing torrc if it exists
    if [[ -f /etc/tor/torrc ]]; then
        sudo cp /etc/tor/torrc /etc/tor/torrc.backup.$(date +%Y%m%d_%H%M%S)
        log_info "Backed up existing Tor configuration"
    fi

    # Generate a random control password
    log_info "Generating secure Tor control password..."
    CONTROL_PASSWORD=$(openssl rand -base64 32)
    HASHED_PASSWORD=$(tor --hash-password "$CONTROL_PASSWORD" | tail -n1)

    # Save the password for user reference (they may need it for advanced configuration)
    echo "Tor Control Password: $CONTROL_PASSWORD" | sudo tee /etc/tor/control_password.txt > /dev/null
    sudo chmod 600 /etc/tor/control_password.txt
    sudo chown root:root /etc/tor/control_password.txt

    # Create basic Tor configuration
    sudo tee /etc/tor/torrc > /dev/null <<EOF
# Tor configuration for End-to-End Chat Application
# Generated by install-dependencies.sh

# Basic settings
DataDirectory /var/lib/tor
PidFile /var/run/tor/tor.pid
RunAsDaemon 1
User debian-tor

# Network settings
SocksPort 9050
ControlPort 9051
HashedControlPassword $HASHED_PASSWORD

# Security settings
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# Client settings
ClientOnly 1
SafeLogging 1
MaxCircuitDirtiness 600

# Bridge settings (uncomment if needed)
# UseBridges 1
# ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
# Bridge obfs4 [bridge-address]:[port] [fingerprint] cert=[certificate] iat-mode=0

# Exit policy (client only)
ExitPolicy reject *:*

# Logging
Log notice file /var/log/tor/notices.log
EOF
    
    # Set proper permissions
    sudo chown root:debian-tor /etc/tor/torrc
    sudo chmod 644 /etc/tor/torrc
    
    # Create log directory
    sudo mkdir -p /var/log/tor
    sudo chown debian-tor:debian-tor /var/log/tor
    
    log_success "Tor configuration created"
}

# Start and enable Tor service
setup_tor_service() {
    log_info "Setting up Tor service..."
    
    # Enable and start Tor service
    sudo systemctl enable tor
    sudo systemctl start tor
    
    # Wait a moment for Tor to start
    sleep 3
    
    # Check if Tor is running
    if sudo systemctl is-active --quiet tor; then
        log_success "Tor service is running"
    else
        log_error "Failed to start Tor service"
        sudo systemctl status tor
        exit 1
    fi
}

# Install Electron dependencies
install_electron_deps() {
    log_info "Installing Electron dependencies..."
    
    case $OS in
        ubuntu|debian)
            sudo apt install -y \
                libnss3-dev \
                libatk-bridge2.0-dev \
                libdrm2 \
                libxcomposite1 \
                libxdamage1 \
                libxrandr2 \
                libgbm1 \
                libxss1 \
                libasound2-dev \
                libgtk-3-dev \
                libxshmfence1
            ;;
        fedora|rhel|centos)
            sudo dnf install -y \
                nss-devel \
                atk-devel \
                libdrm \
                libXcomposite \
                libXdamage \
                libXrandr \
                mesa-libgbm \
                libXScrnSaver \
                alsa-lib-devel \
                gtk3-devel
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm \
                nss \
                atk \
                libdrm \
                libxcomposite \
                libxdamage \
                libxrandr \
                mesa \
                libxss \
                alsa-lib \
                gtk3
            ;;
    esac
    
    log_success "Electron dependencies installed"
}

# Install server dependencies
install_server_deps() {
    log_info "Installing server dependencies..."

    if [[ -d server ]]; then
        pushd server > /dev/null

        # Quiet npm output and avoid deprecated transitive audit/fund noise
        export npm_config_audit=false
        export npm_config_fund=false
        export npm_config_progress=false

        # Install if node_modules missing, otherwise ensure ioredis is present
        if [[ ! -d node_modules ]]; then
            if [[ -f package-lock.json ]]; then
                npm ci --omit=dev
            else
                npm install --omit=dev
            fi
        else
            # Ensure ioredis is available; install if missing
            if ! node -e "require.resolve('ioredis')" >/dev/null 2>&1; then
                log_info "ioredis not found; installing..."
                npm install ioredis@^5 --omit=dev
            fi
        fi

        # Rebuild native modules that may need local toolchain
        npm rebuild better-sqlite3 || true

        popd > /dev/null
        log_success "Server dependencies installed"
    else
        log_warning "server directory not found; skipping server dependency install."
    fi
}

# Install project dependencies
install_project_deps() {
    log_info "Installing project dependencies..."
    
    if [[ ! -f package.json ]]; then
        log_error "package.json not found. Please run this script from the project root directory."
        exit 1
    fi
    
    pnpm install
    log_success "Project dependencies installed"
}

# Create desktop entry
create_desktop_entry() {
    log_info "Creating desktop entry..."

    DESKTOP_FILE="$HOME/.local/share/applications/end2end-chat.desktop"
    PROJECT_DIR=$(pwd)

    mkdir -p "$HOME/.local/share/applications"

    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=End-to-End Chat
Comment=Secure end-to-end encrypted messaging application
Exec=$PROJECT_DIR/install-dependencies.sh --start
Icon=$PROJECT_DIR/assets/icon.png
Terminal=false
Type=Application
Categories=Network;Chat;
StartupWMClass=end2end-chat
EOF

    chmod +x "$DESKTOP_FILE"
    log_success "Desktop entry created"
}

# Start the application
start_application() {
    log_info "Starting End-to-End Chat Application..."

    # Ensure user-local npm bin is on PATH (for pnpm installed to ~/.local)
    export PATH="$HOME/.local/bin:$PATH"

    # Check if Tor is running
    if ! systemctl is-active --quiet tor; then
        log_info "Starting Tor service..."
        sudo systemctl start tor
        sleep 3
    fi

    # Start the application
    log_info "Launching application with pnpm run dev..."
    pnpm run dev
}

# Main installation function
main() {
    log_info "Starting End-to-End Chat Site dependency installation..."

    check_root
    detect_os
    update_packages
    install_system_deps
    install_nodejs
    install_pnpm
    configure_tor
    setup_tor_service
    install_electron_deps
    install_server_deps

    # Only install project deps if we're in the project directory
    if [[ -f package.json ]]; then
        install_project_deps
        create_desktop_entry
    else
        log_warning "Not in project directory. Skipping project-specific setup."
        log_info "Navigate to your project directory and run 'pnpm install' to install project dependencies."
    fi

    log_success "Installation completed successfully!"
    echo
    log_info "Tor is now configured and running on:"
    echo "  - SOCKS proxy: localhost:9050"
    echo "  - Control port: localhost:9051"
    echo
    log_warning "Important security notes:"
    echo "- Change the Tor control password in /etc/tor/torrc"
    echo "- Review Tor configuration for your specific needs"
    echo "- Consider using bridges if in a restricted network"
    echo
    log_info "To start the application, run: $0 --start"
}

# Handle command line arguments
if [[ "$1" == "--start" ]]; then
    # Change to script directory
    cd "$(dirname "$0")"
    start_application
else
    # Run main installation function
    main "$@"
fi