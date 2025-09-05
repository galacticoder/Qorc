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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root. Please run as a regular user."
        exit 1
    fi
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)
            if [[ -f /etc/os-release ]]; then
                . /etc/os-release
                OS=$ID
                OS_VERSION=$VERSION_ID
            else
                log_error "Cannot detect Linux distribution. This script supports Ubuntu/Debian, Fedora/RHEL, Arch Linux, and macOS."
                exit 1
            fi
            ;;
        Darwin*)
            OS="macos"
            OS_VERSION=$(sw_vers -productVersion)
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows"
            OS_VERSION=$(cmd.exe /c ver 2>/dev/null | grep -o '[0-9]*\.[0-9]*\.[0-9]*' | head -1)
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            log_error "This script supports Linux (Ubuntu/Debian, Fedora/RHEL, Arch), macOS, and Windows (WSL/Git Bash)."
            exit 1
            ;;
    esac

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
        macos)
            # Check if Homebrew is installed
            if ! command -v brew &> /dev/null; then
                log_info "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
                # Add Homebrew to PATH for current session
                eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || eval "$(/usr/local/bin/brew shellenv)" 2>/dev/null
            fi
            brew update
            ;;
        windows)
            log_info "Windows detected. Please ensure you have Git Bash, WSL, or similar Unix-like environment."
            log_info "Package management will be handled through Node.js/npm."
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

    # Install packages directly without variables to avoid quoting issues

    # Detect package manager and install accordingly
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        sudo apt-get update
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            log_info "Installing server-only dependencies..."
            sudo apt-get install -y \
                curl wget git build-essential python3 python3-pip python3-dev \
                ca-certificates gnupg2 software-properties-common apt-transport-https \
                lsb-release make gcc g++ libc6-dev which
        else
            log_info "Installing full dependencies (client + server)..."
            sudo apt-get install -y \
                curl wget git build-essential python3 python3-pip python3-dev \
                ca-certificates gnupg2 software-properties-common apt-transport-https \
                lsb-release make gcc g++ libc6-dev which tor torsocks obfs4proxy
        fi
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo dnf install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                ca-certificates gnupg2 which glibc-devel
        else
            sudo dnf install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                tor torsocks obfs4 ca-certificates gnupg2 which glibc-devel
        fi
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo yum install -y epel-release
            sudo yum install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                ca-certificates gnupg2 which glibc-devel
        else
            sudo yum install -y epel-release
            sudo yum install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                tor torsocks obfs4proxy ca-certificates gnupg2 which glibc-devel
        fi
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        # Update package database first
        sudo pacman -Sy --noconfirm
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo pacman -S --noconfirm \
                curl wget git base-devel python python-pip ca-certificates gnupg which
        else
            sudo pacman -S --noconfirm \
                curl wget git base-devel python python-pip \
                tor torsocks obfs4proxy ca-certificates gnupg which
        fi
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        # Refresh repositories first
        sudo zypper refresh
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            # Try to install development pattern first, fallback to individual packages
            sudo zypper install -y -t pattern devel_basis devel_C_C++ || \
            sudo zypper install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                ca-certificates gpg2 which glibc-devel
        else
            sudo zypper install -y -t pattern devel_basis devel_C_C++ || \
            sudo zypper install -y \
                curl wget git gcc gcc-c++ make python3 python3-pip python3-devel \
                tor ca-certificates gpg2 which glibc-devel
        fi
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo apk add --no-cache \
                curl wget git build-base python3 python3-dev py3-pip \
                ca-certificates gnupg which bash make gcc g++ libc-dev
        else
            sudo apk add --no-cache \
                curl wget git build-base python3 python3-dev py3-pip \
                tor ca-certificates gnupg which bash make gcc g++ libc-dev
        fi
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo xbps-install -S \
                curl wget git base-devel python3 python3-devel python3-pip \
                ca-certificates gnupg2 which make gcc
        else
            sudo xbps-install -S \
                curl wget git base-devel python3 python3-devel python3-pip \
                tor ca-certificates gnupg2 which make gcc
        fi
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        # Check if we need to sync first (only if portage tree is very old)
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            log_info "Syncing Portage tree..."
            sudo emerge --sync --quiet || true
        fi
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo emerge --ask=n --quiet \
                net-misc/curl net-misc/wget dev-vcs/git sys-devel/gcc sys-devel/make \
                dev-lang/python dev-python/pip app-crypt/gnupg sys-apps/which sys-libs/glibc
        else
            sudo emerge --ask=n --quiet \
                net-misc/curl net-misc/wget dev-vcs/git sys-devel/gcc sys-devel/make \
                dev-lang/python dev-python/pip net-vpn/tor app-crypt/gnupg sys-apps/which sys-libs/glibc
        fi
    elif command -v eopkg &> /dev/null; then
        # Solus
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo eopkg install -y \
                curl wget git gcc make python3 python3-devel pip \
                ca-certificates gnupg which
        else
            sudo eopkg install -y \
                curl wget git gcc make python3 python3-devel pip \
                tor ca-certificates gnupg which
        fi
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            sudo swupd bundle-add \
                curl wget git c-basic python3-basic devpkg-glibc \
                ca-certificates gnupg which
        else
            sudo swupd bundle-add \
                curl wget git c-basic python3-basic devpkg-glibc \
                network-basic ca-certificates gnupg which
        fi
    elif command -v nix-env &> /dev/null; then
        # NixOS
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            nix-env -iA \
                nixpkgs.curl nixpkgs.wget nixpkgs.git nixpkgs.gcc nixpkgs.gnumake \
                nixpkgs.python3 nixpkgs.python3Packages.pip nixpkgs.gnupg nixpkgs.which
        else
            nix-env -iA \
                nixpkgs.curl nixpkgs.wget nixpkgs.git nixpkgs.gcc nixpkgs.gnumake \
                nixpkgs.python3 nixpkgs.python3Packages.pip nixpkgs.tor nixpkgs.gnupg nixpkgs.which
        fi
    elif [[ "$OS" == "macos" ]]; then
        # macOS
        if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
            brew install curl wget git python@3.11 gnupg
        else
            brew install curl wget git python@3.11 tor torsocks gnupg
        fi

        # Install Xcode command line tools if not present
        if ! xcode-select -p &> /dev/null; then
            log_info "Installing Xcode command line tools..."
            xcode-select --install
            log_warning "Please complete the Xcode command line tools installation and re-run this script."
            exit 1
        fi
    elif [[ "$OS" == "windows" ]]; then
        # Windows
        log_info "Windows detected. Please ensure you have the following installed:"
        echo "  - Git for Windows (includes Git Bash)"
        echo "  - Node.js (will be installed next)"
        echo "  - Python 3.x"
        echo "  - Visual Studio Build Tools or Visual Studio Community"
        if [[ "${SERVER_ONLY:-false}" != "true" ]]; then
            log_warning "Tor installation on Windows requires manual setup."
            log_info "Please download Tor Browser or install Tor as a service manually."
        fi
    else
        log_error "Unsupported operating system or package manager not detected."
        log_info "Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew"
        exit 1
    fi

    log_success "System dependencies installed"
}

# Install Redis server
install_redis() {
    log_info "Installing Redis server..."

    # Check if Redis is already installed and running
    if command -v redis-server &> /dev/null; then
        log_info "Redis is already installed: $(redis-server --version | head -n1)"

        # Check if Redis is running
        if redis-cli ping &> /dev/null; then
            log_success "Redis is already running"
            return 0
        else
            log_info "Redis is installed but not running. Will start it after installation check."
        fi
    fi

    # Detect package manager and install accordingly
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        sudo apt install -y redis-server
        sudo systemctl enable redis-server 2>/dev/null || true
        sudo systemctl start redis-server 2>/dev/null || true
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        sudo dnf install -y redis
        sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || true
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        sudo yum install -y epel-release 2>/dev/null || true
        sudo yum install -y redis
        sudo systemctl enable redis 2>/dev/null || sudo chkconfig redis on 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || sudo service redis start 2>/dev/null || true
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda
        sudo pacman -S --noconfirm redis
        sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || true
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES
        sudo zypper install -y redis
        sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || true
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache redis
        sudo rc-update add redis default 2>/dev/null || true
        sudo rc-service redis start 2>/dev/null || true
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        sudo xbps-install -S redis
        sudo ln -sf /etc/sv/redis /var/service/ 2>/dev/null || true
    elif command -v emerge &> /dev/null; then
        # Gentoo
        sudo emerge --ask=n dev-db/redis
        sudo rc-update add redis default 2>/dev/null || true
        sudo rc-service redis start 2>/dev/null || true
    elif command -v eopkg &> /dev/null; then
        # Solus
        sudo eopkg install -y redis
        sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || true
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        sudo swupd bundle-add redis
        sudo systemctl enable redis 2>/dev/null || true
        sudo systemctl start redis 2>/dev/null || true
    elif command -v nix-env &> /dev/null; then
        # NixOS
        nix-env -iA nixpkgs.redis
        log_warning "NixOS: Please configure Redis service in your configuration.nix"
    elif [[ "$OS" == "macos" ]]; then
        # macOS
        brew install redis
        brew services start redis
    elif [[ "$OS" == "windows" ]]; then
        # Windows
        log_warning "Redis installation on Windows requires manual setup."
        log_info "Please download Redis for Windows from: https://github.com/microsoftarchive/redis/releases"
        log_info "Or use Windows Subsystem for Linux (WSL) for easier Redis installation."
        return 0
    else
        log_error "Unsupported OS for Redis installation"
        log_info "Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew"
        return 1
    fi

    # Verify Redis installation
    if command -v redis-server &> /dev/null; then
        log_success "Redis server installed successfully"

        # Test Redis connection
        if redis-cli ping &> /dev/null; then
            log_success "Redis is running and responding to ping"
        else
            log_warning "Redis is installed but not responding. You may need to start it manually."
        fi
    else
        log_error "Redis installation failed"
        return 1
    fi
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

    # Detect package manager and install accordingly
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian/Mint/Pop!_OS/Elementary
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt install -y nodejs
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+/CentOS 8+/Rocky Linux/AlmaLinux/Amazon Linux 2022+
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo dnf install -y nodejs npm
    elif command -v yum &> /dev/null; then
        # CentOS 7/RHEL 7/Amazon Linux 2/Oracle Linux
        curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
        sudo yum install -y nodejs npm
    elif command -v pacman &> /dev/null; then
        # Arch Linux/Manjaro/EndeavourOS/Garuda/ArcoLinux/Artix
        sudo pacman -Sy --noconfirm
        sudo pacman -S --noconfirm nodejs npm
    elif command -v zypper &> /dev/null; then
        # openSUSE Leap/Tumbleweed/SLES/openSUSE MicroOS
        sudo zypper refresh
        # Try different Node.js versions - prefer newer versions
        sudo zypper install -y nodejs20 npm20 || \
        sudo zypper install -y nodejs18 npm18 || \
        sudo zypper install -y nodejs npm
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache nodejs npm
    elif command -v xbps-install &> /dev/null; then
        # Void Linux
        sudo xbps-install -S nodejs npm
    elif command -v emerge &> /dev/null; then
        # Gentoo/Funtoo/Calculate Linux
        # Check if we need to sync first
        if [ ! -d /var/db/repos/gentoo ] || [ $(find /var/db/repos/gentoo -name "*.ebuild" -mtime +7 | wc -l) -eq 0 ]; then
            sudo emerge --sync --quiet || true
        fi
        # Install Node.js with npm support
        sudo emerge --ask=n --quiet net-libs/nodejs
    elif command -v eopkg &> /dev/null; then
        # Solus
        sudo eopkg install -y nodejs npm
    elif command -v swupd &> /dev/null; then
        # Clear Linux
        sudo swupd bundle-add nodejs-basic
    elif command -v nix-env &> /dev/null; then
        # NixOS
        nix-env -iA nixpkgs.nodejs nixpkgs.nodePackages.npm
    elif [[ "$OS" == "macos" ]]; then
        # macOS
        brew install node@20 || brew install node
        # Try to link the specific version if available
        brew link node@20 --force 2>/dev/null || true
    elif [[ "$OS" == "windows" ]]; then
        # Windows
        log_info "Please download and install Node.js from: https://nodejs.org/"
        log_info "Choose the LTS version (20.x or later)"
        log_warning "After installing Node.js, restart your terminal and re-run this script."
        read -p "Press Enter after installing Node.js to continue..."

        # Verify installation
        if ! command -v node &> /dev/null; then
            log_error "Node.js not found. Please install it and restart your terminal."
            exit 1
        fi
    else
        log_error "Unsupported operating system or package manager for Node.js installation"
        log_info "Supported package managers: apt-get, dnf, yum, pacman, zypper, apk, xbps-install, emerge, eopkg, swupd, nix-env, brew"
        log_info "Please install Node.js 20+ manually from: https://nodejs.org/"
        exit 1
    fi

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

    # Install pnpm globally
    log_info "Installing pnpm@$PNPM_VER globally"

    # Try corepack first (preferred method)
    if command -v corepack &> /dev/null; then
        log_info "Using corepack to enable pnpm globally..."
        sudo corepack enable pnpm || {
            log_warning "Corepack failed, trying npm global installation..."
            timeout 120 sudo npm install -g "pnpm@${PNPM_VER}" --no-audit --no-fund --silent || {
                log_warning "npm install timed out or failed, trying manual installation..."
                # Try manual binary download as last resort
                log_info "Downloading pnpm binary globally..."
                sudo mkdir -p /usr/local/bin
                curl -fsSL https://github.com/pnpm/pnpm/releases/latest/download/pnpm-linuxstatic-x64 -o /tmp/pnpm || true
                sudo mv /tmp/pnpm /usr/local/bin/pnpm 2>/dev/null || true
                sudo chmod +x /usr/local/bin/pnpm 2>/dev/null || true
            }
        }
    else
        # Fallback to npm if corepack not available
        log_info "Using npm to install pnpm globally..."
        timeout 120 sudo npm install -g "pnpm@${PNPM_VER}" --no-audit --no-fund --silent || {
            log_warning "npm install timed out or failed, trying manual installation..."
            # Try manual binary download as last resort
            log_info "Downloading pnpm binary globally..."
            sudo mkdir -p /usr/local/bin
            curl -fsSL https://github.com/pnpm/pnpm/releases/latest/download/pnpm-linuxstatic-x64 -o /tmp/pnpm || true
            sudo mv /tmp/pnpm /usr/local/bin/pnpm 2>/dev/null || true
            sudo chmod +x /usr/local/bin/pnpm 2>/dev/null || true
        }
    fi

    # Ensure global bin directories are on PATH for current script
    export PATH="/usr/local/bin:$PATH"

    if command -v pnpm &> /dev/null; then
        log_success "pnpm installed: $(pnpm --version)"
    else
        log_error "pnpm did not install correctly. Check npm configuration and PATH."
        exit 1
    fi
}

# Configure Tor
configure_tor() {
    if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
        log_info "Skipping Tor configuration in server-only mode..."
        return
    fi

    log_info "Configuring Tor..."

    case $OS in
        ubuntu|debian|fedora|rhel|centos|arch|manjaro)
            # Linux configuration
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
            ;;
        macos)
            # macOS configuration
            TOR_CONFIG_DIR="/usr/local/etc/tor"
            sudo mkdir -p "$TOR_CONFIG_DIR"

            # Backup existing torrc if it exists
            if [[ -f "$TOR_CONFIG_DIR/torrc" ]]; then
                sudo cp "$TOR_CONFIG_DIR/torrc" "$TOR_CONFIG_DIR/torrc.backup.$(date +%Y%m%d_%H%M%S)"
                log_info "Backed up existing Tor configuration"
            fi

            # Generate a random control password
            log_info "Generating secure Tor control password..."
            CONTROL_PASSWORD=$(openssl rand -base64 32)
            HASHED_PASSWORD=$(tor --hash-password "$CONTROL_PASSWORD" | tail -n1)

            # Save the password for user reference
            echo "Tor Control Password: $CONTROL_PASSWORD" | sudo tee "$TOR_CONFIG_DIR/control_password.txt" > /dev/null
            sudo chmod 600 "$TOR_CONFIG_DIR/control_password.txt"

            # Create basic Tor configuration for macOS
            sudo tee "$TOR_CONFIG_DIR/torrc" > /dev/null <<EOF
# Tor configuration for End-to-End Chat Application (macOS)
# Generated by install-dependencies.sh

# Basic settings
DataDirectory /usr/local/var/lib/tor
PidFile /usr/local/var/run/tor.pid
RunAsDaemon 1

# Network settings
SocksPort 9050
ControlPort 9051
HashedControlPassword $HASHED_PASSWORD

# Security settings
CookieAuthentication 1

# Client settings
ClientOnly 1
SafeLogging 1
MaxCircuitDirtiness 600

# Exit policy (client only)
ExitPolicy reject *:*

# Logging
Log notice file /usr/local/var/log/tor/notices.log
EOF

            # Create log directory
            sudo mkdir -p /usr/local/var/log/tor
            sudo mkdir -p /usr/local/var/lib/tor
            sudo mkdir -p /usr/local/var/run
            ;;
        windows)
            log_warning "Tor configuration on Windows requires manual setup."
            log_info "Please configure Tor manually or use Tor Browser."
            log_info "Default SOCKS proxy should be available at localhost:9050"
            return
            ;;
    esac

    log_success "Tor configuration created"
}

# Start and enable Tor service
setup_tor_service() {
    if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
        log_info "Skipping Tor service setup in server-only mode..."
        return
    fi

    log_info "Setting up Tor service..."

    case $OS in
        ubuntu|debian|fedora|rhel|centos|arch|manjaro)
            # Linux systemd service
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
            ;;
        macos)
            # macOS service via Homebrew
            log_info "Starting Tor service on macOS..."

            # Start Tor service
            brew services start tor

            # Wait a moment for Tor to start
            sleep 3

            # Check if Tor is running
            if pgrep -f "tor" > /dev/null; then
                log_success "Tor service is running"
            else
                log_warning "Tor may not be running. You can start it manually with: brew services start tor"
            fi
            ;;
        windows)
            log_warning "Tor service setup on Windows requires manual configuration."
            log_info "Please start Tor Browser or configure Tor as a Windows service manually."
            ;;
    esac
}

# Install Electron dependencies
install_electron_deps() {
    if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
        log_info "Skipping Electron dependencies in server-only mode..."
        return
    fi

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
        macos)
            log_info "Electron dependencies are handled automatically on macOS"
            # No additional system dependencies needed for Electron on macOS
            ;;
        windows)
            log_info "Electron dependencies are handled automatically on Windows"
            # No additional system dependencies needed for Electron on Windows
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

# Create symbolic links for configuration files
create_config_symlinks() {
    log_info "Creating symbolic links for configuration files..."

    # Define the configuration files that should be symlinked from config/ to root
    declare -A CONFIG_FILES=(
        ["components.json"]="config/components.json"
        ["eslint.config.js"]="config/eslint.config.js"
        ["postcss.config.js"]="config/postcss.config.js"
        ["tailwind.config.ts"]="config/tailwind.config.ts"
        ["tsconfig.app.json"]="config/tsconfig.app.json"
        ["tsconfig.json"]="config/tsconfig.json"
        ["tsconfig.node.json"]="config/tsconfig.node.json"
        ["vite.config.ts"]="config/vite.config.ts"
    )

    for symlink_name in "${!CONFIG_FILES[@]}"; do
        target_file="${CONFIG_FILES[$symlink_name]}"

        # Check if target file exists in config directory
        if [[ -f "$target_file" ]]; then
            # Remove existing symlink or file if it exists
            if [[ -L "$symlink_name" ]] || [[ -f "$symlink_name" ]]; then
                rm -f "$symlink_name"
                log_info "Removed existing $symlink_name"
            fi

            # Create the symbolic link
            ln -s "$target_file" "$symlink_name"
            log_info "Created symlink: $symlink_name -> $target_file"
        else
            log_warning "Target file $target_file not found, skipping symlink creation for $symlink_name"
        fi
    done

    log_success "Configuration symbolic links created"
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
    if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
        log_info "Skipping desktop entry in server-only mode..."
        return
    fi

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

    # Normalize SERVER_ONLY environment variable
    SERVER_ONLY=$(normalize_bool "${SERVER_ONLY:-}" "false")
    export SERVER_ONLY

    check_root
    detect_os
    update_packages
    install_system_deps
    install_redis
    install_nodejs
    install_pnpm
    configure_tor
    setup_tor_service
    install_electron_deps
    install_server_deps

    # Only install project deps if we're in the project directory
    if [[ -f package.json ]]; then
        install_project_deps
        create_config_symlinks
        create_desktop_entry
    else
        log_warning "Not in project directory. Skipping project-specific setup."
        log_info "Navigate to your project directory and run 'pnpm install' to install project dependencies."
    fi

    log_success "Installation completed successfully!"
    echo

    if [[ "${SERVER_ONLY:-false}" == "true" ]]; then
        log_info "Server-only installation complete!"
        log_info "Server is starting..."
    else
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
    fi
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