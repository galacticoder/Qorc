#!/bin/bash

# Script: setup_chat_docker.sh
# Purpose: Build and run end2end-chat-site server in Docker

set -e  # Exit on error

# Configuration
SERVER_IMAGE_NAME="end2end-chat-server"
SERVER_CONTAINER_NAME="chat-server-container"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${PURPLE}[STEP]${NC} $1"; }
log_header() { echo -e "${CYAN}=== $1 ===${NC}"; }

# Check if Docker is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        log_info "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info > /dev/null 2>&1; then
        log_warning "Docker daemon is not running or permission denied."

        # Try to start Docker daemon
        log_step "Attempting to start Docker daemon..."
        if sudo systemctl start docker 2>/dev/null; then
            log_success "Docker daemon started successfully"
            sleep 2  # Give Docker a moment to fully start
        else
            log_warning "Could not start Docker daemon automatically"
        fi

        # Check if it's a permission issue
        if docker info > /dev/null 2>&1; then
            log_success "Docker is now ready!"
        elif docker info 2>&1 | grep -q "permission denied"; then
            log_step "Fixing Docker permissions..."

            # Add user to docker group
            sudo usermod -aG docker $USER
            log_info "Added $USER to docker group"

            # Try to apply group changes and restart script
            log_step "Applying group changes and restarting script..."
            if command -v newgrp > /dev/null; then
                log_info "Restarting with updated permissions..."
                exec newgrp docker bash -c "cd '$PWD' && '$0' $*"
            else
                log_warning "Please log out and back in, or restart your terminal"
                log_info "Then run this script again"
                exit 1
            fi
        else
            log_error "Docker is still not accessible. Please check Docker installation."
            exit 1
        fi
    fi

    log_success "Docker is ready!"
}

# Validate project structure
validate_project() {
    if [ ! -f "Dockerfile" ]; then
        log_error "Dockerfile not found. Run this script from the project root."
        exit 1
    fi
    
    if [ ! -d "server" ]; then
        log_error "Server directory not found. Run this script from the project root."
        exit 1
    fi
    
    log_success "Project structure validated"
}

# Build Docker image
build_image() {
    log_step "Building Docker image '$SERVER_IMAGE_NAME'..."
    
    if docker image inspect $SERVER_IMAGE_NAME > /dev/null 2>&1; then
        log_warning "Image '$SERVER_IMAGE_NAME' already exists."
        read -p "Rebuild? (y/N): " rebuild
        if [[ ! $rebuild =~ ^[Yy]$ ]]; then
            log_info "Using existing image."
            return
        fi
        docker rmi $SERVER_IMAGE_NAME > /dev/null 2>&1 || true
    fi
    
    if ! docker build -t $SERVER_IMAGE_NAME .; then
        log_error "Failed to build Docker image"
        exit 1
    fi
    
    log_success "Docker image built successfully!"
}

# Run server container
run_server() {
    log_step "Starting server container..."
    
    # Stop existing container if running
    docker stop $SERVER_CONTAINER_NAME 2>/dev/null || true
    docker rm $SERVER_CONTAINER_NAME 2>/dev/null || true
    
    log_info "Server will be available at:"
    log_info "  HTTP:  http://localhost:8080"
    log_info "  HTTPS: https://localhost:8443"
    echo ""
    log_warning "Press Ctrl+C to stop the server"
    echo ""
    
    # Run container interactively
    docker run -it --rm \
        --name $SERVER_CONTAINER_NAME \
        -p 8080:8080 \
        -p 8443:8443 \
        $SERVER_IMAGE_NAME
}

# Cleanup Docker resources
cleanup() {
    log_step "Cleaning up Docker resources..."
    
    # Stop and remove container
    if docker ps -a --format '{{.Names}}' | grep -q "^${SERVER_CONTAINER_NAME}\$"; then
        log_info "Removing container: $SERVER_CONTAINER_NAME"
        docker stop $SERVER_CONTAINER_NAME > /dev/null 2>&1 || true
        docker rm $SERVER_CONTAINER_NAME > /dev/null 2>&1 || true
    fi
    
    # Remove image
    if docker image inspect $SERVER_IMAGE_NAME > /dev/null 2>&1; then
        log_info "Removing image: $SERVER_IMAGE_NAME"
        docker rmi $SERVER_IMAGE_NAME > /dev/null 2>&1 || true
    fi
    
    # Clean up unused resources
    docker system prune -f > /dev/null 2>&1 || true
    
    log_success "Cleanup complete!"
}

# Show menu and get user choice
show_menu() {
    log_header "End-to-End Chat Site Server Docker Setup"
    echo ""
    log_info "What would you like to do?"
    echo "1) Run Server (Backend - Node.js) in Docker"
    echo "2) Clean up Docker images and containers"
    echo "3) Exit"
    echo ""
    log_info "Note: For the client (Electron app), run './startClient.sh' directly"
    echo ""
    read -p "Enter your choice (1-3): " choice
}

# Main execution
main() {
    check_docker
    validate_project

    show_menu

    case $choice in
        1)
            build_image
            run_server
            log_success "Server session ended."
            log_info "To run the client: ./startClient.sh"
            ;;
        2)
            cleanup
            ;;
        3)
            log_info "Exiting..."
            exit 0
            ;;
        *)
            log_error "Invalid choice. Please run the script again."
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
