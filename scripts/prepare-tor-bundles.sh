#!/bin/bash

# Prepare Tor Expert Bundles for production builds
# This script downloads the latest Tor Expert Bundles and organizes them for electron-builder
# Usage: ./prepare-tor-bundles.sh [--all-platforms]

set -e

TOR_VERSION="15.0a2"
BASE_URL="https://archive.torproject.org/tor-package-archive/torbrowser"
BUNDLE_DIR="tor-bundles"
ALL_PLATFORMS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --all-platforms)
            ALL_PLATFORMS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--all-platforms]"
            exit 1
            ;;
    esac
done

# Detect current OS
CURRENT_OS=$(uname -s)
case "$CURRENT_OS" in
    Linux*)
        HOST_PLATFORM="linux"
        ;;
    Darwin*)
        HOST_PLATFORM="macos"
        ;;
    MINGW*|CYGWIN*|MSYS*)
        HOST_PLATFORM="windows"
        ;;
    *)
        echo "Unsupported operating system: $CURRENT_OS"
        exit 1
        ;;
esac

if [ "$ALL_PLATFORMS" = true ]; then
    echo "Preparing Tor Expert Bundles v${TOR_VERSION} for all platforms..."
    PLATFORMS=("linux" "macos" "windows")
else
    echo "Preparing Tor Expert Bundle v${TOR_VERSION} for current platform: $HOST_PLATFORM..."
    PLATFORMS=("$HOST_PLATFORM")
fi

# Create bundle directories
for platform in "${PLATFORMS[@]}"; do
    mkdir -p "${BUNDLE_DIR}/${platform}"
done

# Function to download and extract Tor bundle
download_and_extract() {
    local platform=$1
    local arch=$2
    local filename=$3
    local target_dir=$4
    
    local url="${BASE_URL}/${TOR_VERSION}/${filename}"
    local archive_path="/tmp/${filename}"
    
    echo "Downloading ${filename}..."
    
    if command -v curl >/dev/null 2>&1; then
        curl -L -o "${archive_path}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${archive_path}" "${url}"
    else
        echo "Error: Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    echo "Extracting to ${target_dir}..."
    
    # Extract archive
    case "${filename}" in
        *.tar.gz)
            tar -xzf "${archive_path}" -C "${target_dir}" --strip-components=1
            ;;
        *)
            echo "Error: Unsupported archive format: ${filename}"
            exit 1
            ;;
    esac
    
    # Clean up archive
    rm -f "${archive_path}"
    
    # Make binaries executable
    if [[ "${platform}" != "windows" ]]; then
        find "${target_dir}" -name "tor" -type f -exec chmod +x {} \;
        find "${target_dir}" -name "lyrebird" -type f -exec chmod +x {} \;
        find "${target_dir}" -name "conjure-client" -type f -exec chmod +x {} \;
        find "${target_dir}" -name "obfs4proxy" -type f -exec chmod +x {} \; # Legacy support
        find "${target_dir}" -name "snowflake-client" -type f -exec chmod +x {} \;
    fi
    
    echo "${platform} ${arch} bundle ready"
}

# Download bundles for selected platforms
for platform in "${PLATFORMS[@]}"; do
    case $platform in
        linux)
            echo "Preparing Linux bundles..."
            download_and_extract "linux" "x64" "tor-expert-bundle-linux-x86_64-${TOR_VERSION}.tar.gz" "${BUNDLE_DIR}/linux"
            ;;
        macos)
            echo "Preparing macOS bundles..."
            download_and_extract "macos" "x64" "tor-expert-bundle-macos-x86_64-${TOR_VERSION}.tar.gz" "${BUNDLE_DIR}/macos"
            ;;
        windows)
            echo "Preparing Windows bundles..."
            download_and_extract "windows" "x64" "tor-expert-bundle-windows-x86_64-${TOR_VERSION}.tar.gz" "${BUNDLE_DIR}/windows"
            ;;
    esac
done

# Verify binaries exist
echo "Verifying bundles..."

check_binary() {
    local platform=$1
    local binary_name=$2
    local path="${BUNDLE_DIR}/${platform}/${binary_name}"
    
    if [[ -f "${path}" ]]; then
        echo "${platform}/${binary_name} - OK"
        return 0
    else
        echo "${platform}/${binary_name} - MISSING"
        return 1
    fi
}

# Check all required binaries for selected platforms
all_good=true

for platform in "${PLATFORMS[@]}"; do
    case $platform in
        linux|macos)
            check_binary "$platform" "tor" || all_good=false
            check_binary "$platform" "pluggable_transports/lyrebird" || all_good=false
            ;;
        windows)
            check_binary "$platform" "tor.exe" || all_good=false
            check_binary "$platform" "pluggable_transports/lyrebird.exe" || all_good=false
            ;;
    esac
done

if [[ "$all_good" == "true" ]]; then
    echo ""
    echo "All Tor Expert Bundles prepared successfully!"
    echo ""
    echo "Bundle structure:"
    for platform in "${PLATFORMS[@]}"; do
        echo "   tor-bundles/$platform/     ($platform x64 binaries)"
    done
    echo ""
    echo "Total bundle size: $(du -sh ${BUNDLE_DIR} | cut -f1)"
    echo ""
    echo "You can now run 'pnpm run electron-build' to create production builds with bundled Tor."
else
    echo ""
    echo "Some bundles are incomplete. Please check the errors above."
    exit 1
fi
