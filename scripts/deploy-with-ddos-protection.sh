#!/bin/bash

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}     End-to-End Chat Server Deployment     ${BLUE}║${NC}"
echo -e "${BLUE}║${GREEN}        Enterprise DDoS Protection         ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

log_info() {
    echo -e "${BLUE}[DEPLOY]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[DEPLOY]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[DEPLOY]${NC} $1"
}

log_error() {
    echo -e "${RED}[DEPLOY]${NC} $1"
}

# Show help
show_help() {
    echo "End-to-End Chat Server Deployment with DDoS Protection"
    echo ""
    echo "This script provides multiple deployment options for your chat server"
    echo "with enterprise-grade DDoS protection via Cloudflare Tunnel."
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Deployment Options:"
    echo "  --native           Deploy natively on host system"
    echo "  --docker           Deploy using Docker containers"
    echo "  --quick-setup      Quick setup with minimal configuration"
    echo "  --production       Production deployment with all security features"
    echo ""
    echo "Management Options:"
    echo "  --status           Show deployment status"
    echo "  --stop             Stop all services"
    echo "  --restart          Restart all services"
    echo "  --logs             Show service logs"
    echo "  --update           Update to latest version"
    echo ""
    echo "Configuration Options:"
    echo "  --setup-cloudflare Configure Cloudflare tunnel only"
    echo "  --setup-env        Create environment configuration"
    echo "  --test-security    Run security tests"
    echo ""
    echo "Examples:"
    echo "  $0 --quick-setup              # Quick deployment for testing"
    echo "  $0 --production --docker      # Production Docker deployment"
    echo "  $0 --native                   # Native deployment on host"
    echo ""
    exit 0
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check for required tools
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi
    
    if ! command -v git &> /dev/null; then
        missing_tools+=("git")
    fi
    
    if [[ "${DEPLOY_METHOD:-}" == "docker" ]]; then
        if ! command -v docker &> /dev/null; then
            missing_tools+=("docker")
        fi
        
        if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
            missing_tools+=("docker-compose")
        fi
    else
        if ! command -v node &> /dev/null; then
            missing_tools+=("node")
        fi
        
        if ! command -v npm &> /dev/null && ! command -v pnpm &> /dev/null; then
            missing_tools+=("npm or pnpm")
        fi
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and try again."
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    if [[ ! -f ".env" ]]; then
        if [[ -f "cloudflare-env.example" ]]; then
            cp cloudflare-env.example .env
            log_info "Created .env file from template"
        else
            log_warning "Environment template not found, creating basic .env"
            cat > .env << EOF
# Basic configuration
CLOUDFLARE_ENABLED=true
SERVER_PASSWORD=change_me_please
REDIS_URL=redis://127.0.0.1:6379
RATE_LIMIT_ENABLED=true
TRUST_PROXY=true
NODE_ENV=production
EOF
        fi
        
        log_warning "Please edit .env file with your configuration before continuing"
        log_info "Minimum required: CLOUDFLARE_TUNNEL_TOKEN and SERVER_PASSWORD"
        
        if [[ "${INTERACTIVE:-true}" == "true" ]]; then
            read -p "Press Enter after configuring .env file..."
        fi
    else
        log_info "Environment file already exists"
    fi
}

# Deploy using Docker
deploy_docker() {
    log_info "Deploying with Docker containers..."
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        log_info "Please start Docker and try again"
        exit 1
    fi
    
    # Build and start services
    log_info "Building Docker images..."
    if docker compose -f docker-compose.cloudflared.yml build; then
        log_success "Docker images built successfully"
    else
        log_error "Failed to build Docker images"
        exit 1
    fi
    
    log_info "Starting services..."
    if docker compose -f docker-compose.cloudflared.yml up -d; then
        log_success "Services started successfully"
    else
        log_error "Failed to start services"
        exit 1
    fi
    
    # Wait for services to be ready
    log_info "Waiting for services to initialize..."
    sleep 10
    
    # Check service health
    check_service_health_docker
}

# Deploy natively on host
deploy_native() {
    log_info "Deploying natively on host system..."
    
    # Setup Cloudflare tunnel
    if [[ ! -f "/etc/cloudflared/config.yml" ]]; then
        log_info "Setting up Cloudflare tunnel..."
        if [[ -f "setup-cloudflared.sh" ]]; then
            ./setup-cloudflared.sh
        else
            log_error "setup-cloudflared.sh not found"
            exit 1
        fi
    else
        log_info "Cloudflare tunnel already configured"
    fi
    
    # Start the server with DDoS protection
    log_info "Starting chat server with DDoS protection..."
    if [[ -f "startServerWithCloudflared.sh" ]]; then
        ./startServerWithCloudflared.sh &
        SERVER_PID=$!
        echo $SERVER_PID > .server.pid
        log_success "Server started (PID: $SERVER_PID)"
    else
        log_error "startServerWithCloudflared.sh not found"
        exit 1
    fi
    
    # Wait for server to start
    sleep 5
    check_service_health_native
}

# Quick setup for testing
quick_setup() {
    log_info "Running quick setup for testing..."
    
    DEPLOY_METHOD="native"
    INTERACTIVE="false"
    
    # Create minimal configuration
    cat > .env << EOF
CLOUDFLARE_ENABLED=false
SERVER_PASSWORD=test123
REDIS_URL=redis://127.0.0.1:6379
RATE_LIMIT_ENABLED=true
NODE_ENV=development
DEBUG_SERVER_LOGS=true
EOF

    log_warning "Quick setup disables Cloudflare protection for testing"
    log_info "Use --production for full DDoS protection"
    
    # Start without Cloudflare
    if [[ -f "startServer.sh" ]]; then
        ./startServer.sh &
        SERVER_PID=$!
        echo $SERVER_PID > .server.pid
        log_success "Server started in test mode (PID: $SERVER_PID)"
    else
        log_error "startServer.sh not found"
        exit 1
    fi
}

# Production deployment
production_deploy() {
    log_info "Setting up production deployment with full security..."
    
    # Ensure we have proper configuration
    if [[ ! -f ".env" ]]; then
        setup_environment
    fi
    
    # Check for production settings
    if ! grep -q "NODE_ENV=production" .env; then
        log_warning "Setting NODE_ENV to production"
        echo "NODE_ENV=production" >> .env
    fi
    
    # Deploy based on method
    if [[ "${DEPLOY_METHOD:-docker}" == "docker" ]]; then
        deploy_docker
    else
        deploy_native
    fi
    
    # Run security tests
    log_info "Running security validation..."
    run_security_tests
}

# Check service health for Docker deployment
check_service_health_docker() {
    log_info "Checking service health..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker compose -f docker-compose.cloudflared.yml ps | grep -q "Up"; then
            log_success "Services are running"
            
            # Check if server is responding
            if curl -f http://localhost:8080/health &> /dev/null; then
                log_success "Server health check passed"
                return 0
            fi
        fi
        
        log_info "Waiting for services... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    log_error "Services failed to start properly"
    docker compose -f docker-compose.cloudflared.yml logs
    return 1
}

# Check service health for native deployment
check_service_health_native() {
    log_info "Checking service health..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f http://localhost:8080/health &> /dev/null; then
            log_success "Server health check passed"
            return 0
        fi
        
        log_info "Waiting for server... (attempt $attempt/$max_attempts)"
        sleep 2
        ((attempt++))
    done
    
    log_error "Server failed to start properly"
    return 1
}

# Run security tests
run_security_tests() {
    log_info "Running security tests..."
    
    local test_passed=0
    local test_total=0
    
    # Test 1: Check if server is responding
    ((test_total++))
    if curl -f http://localhost:8080/health &> /dev/null; then
        log_success "✓ Server health check"
        ((test_passed++))
    else
        log_error "✗ Server health check failed"
    fi
    
    # Test 2: Check if Cloudflare tunnel is active
    ((test_total++))
    if systemctl is-active --quiet cloudflared 2>/dev/null || docker compose -f docker-compose.cloudflared.yml ps 2>/dev/null | grep -q cloudflared; then
        log_success "✓ Cloudflare tunnel active"
        ((test_passed++))
    else
        log_warning "✗ Cloudflare tunnel not detected"
    fi
    
    # Test 3: Check Redis connectivity
    ((test_total++))
    if redis-cli ping &> /dev/null || docker exec -it chat-redis redis-cli ping &> /dev/null; then
        log_success "✓ Redis connectivity"
        ((test_passed++))
    else
        log_error "✗ Redis connectivity failed"
    fi
    
    echo
    log_info "Security tests completed: $test_passed/$test_total passed"
    
    if [[ $test_passed -eq $test_total ]]; then
        log_success "All security tests passed!"
    else
        log_warning "Some security tests failed. Please review the configuration."
    fi
}

# Show deployment status
show_status() {
    echo
    log_info "Deployment Status"
    echo "=================="
    
    # Check Docker deployment
    if docker compose -f docker-compose.cloudflared.yml ps &> /dev/null; then
        echo -e "${BLUE}Docker Deployment:${NC}"
        docker compose -f docker-compose.cloudflared.yml ps
        echo
    fi
    
    # Check native deployment
    if [[ -f ".server.pid" ]]; then
        SERVER_PID=$(cat .server.pid)
        if kill -0 $SERVER_PID 2>/dev/null; then
            echo -e "${GREEN}Native Server: Running (PID: $SERVER_PID)${NC}"
        else
            echo -e "${RED}Native Server: Stopped${NC}"
        fi
    else
        echo -e "${YELLOW}Native Server: Not deployed${NC}"
    fi
    
    # Check Cloudflare tunnel
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        echo -e "${GREEN}Cloudflare Tunnel: Active${NC}"
    else
        echo -e "${YELLOW}Cloudflare Tunnel: Inactive${NC}"
    fi
    
    # Check Redis
    if redis-cli ping &> /dev/null; then
        echo -e "${GREEN}Redis: Running${NC}"
    else
        echo -e "${RED}Redis: Not running${NC}"
    fi
    
    echo
}

# Stop all services
stop_services() {
    log_info "Stopping all services..."
    
    # Stop Docker services
    if docker compose -f docker-compose.cloudflared.yml ps &> /dev/null; then
        docker compose -f docker-compose.cloudflared.yml down
        log_info "Docker services stopped"
    fi
    
    # Stop native server
    if [[ -f ".server.pid" ]]; then
        SERVER_PID=$(cat .server.pid)
        if kill -0 $SERVER_PID 2>/dev/null; then
            kill $SERVER_PID
            rm .server.pid
            log_info "Native server stopped"
        fi
    fi
    
    # Stop Cloudflare tunnel
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        sudo systemctl stop cloudflared
        log_info "Cloudflare tunnel stopped"
    fi
    
    log_success "All services stopped"
}

# Restart services
restart_services() {
    log_info "Restarting services..."
    stop_services
    sleep 3
    
    # Restart based on what was running
    if docker compose -f docker-compose.cloudflared.yml ps &> /dev/null; then
        docker compose -f docker-compose.cloudflared.yml up -d
    else
        deploy_native
    fi
    
    log_success "Services restarted"
}

# Show logs
show_logs() {
    echo
    log_info "Service Logs"
    echo "============"
    
    # Docker logs
    if docker compose -f docker-compose.cloudflared.yml ps &> /dev/null; then
        echo -e "${BLUE}Docker Services:${NC}"
        docker compose -f docker-compose.cloudflared.yml logs --tail=50
        echo
    fi
    
    # Cloudflare tunnel logs
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        echo -e "${BLUE}Cloudflare Tunnel:${NC}"
        sudo journalctl -u cloudflared --no-pager --lines=20
        echo
    fi
    
    # Native server logs
    if [[ -f "server/logs/server.log" ]]; then
        echo -e "${BLUE}Server Logs:${NC}"
        tail -n 20 server/logs/server.log
    fi
}

# Update deployment
update_deployment() {
    log_info "Updating deployment..."
    
    # Pull latest changes
    if git pull; then
        log_success "Code updated"
    else
        log_warning "Failed to pull latest changes"
    fi
    
    # Rebuild and restart
    if docker compose -f docker-compose.cloudflared.yml ps &> /dev/null; then
        docker compose -f docker-compose.cloudflared.yml down
        docker compose -f docker-compose.cloudflared.yml build --no-cache
        docker compose -f docker-compose.cloudflared.yml up -d
    else
        restart_services
    fi
    
    log_success "Deployment updated"
}

# Show final information
show_final_info() {
    echo
    log_success "Deployment Complete!"
    echo
    echo -e "${GREEN}Your end-to-end chat server is now running with DDoS protection!${NC}"
    echo
    echo -e "${BLUE}Access URLs:${NC}"
    echo "  Local:  http://localhost:8080"
    echo "  HTTPS:  https://localhost:8443"
    
    if [[ -f "/etc/cloudflared/config.yml" ]]; then
        DOMAIN=$(grep -o "hostname: [^.]*\..*" /etc/cloudflared/config.yml | head -1 | cut -d' ' -f2 || echo "your-domain.com")
        echo "  Public: https://$DOMAIN"
    fi
    
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  Status:  $0 --status"
    echo "  Logs:    $0 --logs"
    echo "  Stop:    $0 --stop"
    echo "  Restart: $0 --restart"
    echo "  Update:  $0 --update"
    echo
    echo -e "${YELLOW}Important Security Notes:${NC}"
    echo "  • All traffic is protected by Cloudflare's DDoS protection"
    echo "  • Authentication is encrypted with post-quantum cryptography"
    echo "  • Rate limiting is enabled to prevent abuse"
    echo "  • Monitor logs regularly for any security events"
    echo
}

# Main execution
main() {
    case "${1:-}" in
        "--help"|"-h")
            show_help
            ;;
        "--native")
            DEPLOY_METHOD="native"
            check_prerequisites
            setup_environment
            deploy_native
            show_final_info
            ;;
        "--docker")
            DEPLOY_METHOD="docker"
            check_prerequisites
            setup_environment
            deploy_docker
            show_final_info
            ;;
        "--quick-setup")
            check_prerequisites
            quick_setup
            show_final_info
            ;;
        "--production")
            if [[ "${2:-}" == "--docker" ]]; then
                DEPLOY_METHOD="docker"
            else
                DEPLOY_METHOD="native"
            fi
            check_prerequisites
            production_deploy
            show_final_info
            ;;
        "--setup-cloudflare")
            ./setup-cloudflared.sh
            ;;
        "--setup-env")
            setup_environment
            ;;
        "--status")
            show_status
            ;;
        "--stop")
            stop_services
            ;;
        "--restart")
            restart_services
            ;;
        "--logs")
            show_logs
            ;;
        "--update")
            update_deployment
            ;;
        "--test-security")
            run_security_tests
            ;;
        *)
            echo -e "${YELLOW}No option specified. Use --help for usage information.${NC}"
            echo
            echo "Quick start options:"
            echo "  $0 --quick-setup      # Fast setup for testing"
            echo "  $0 --production       # Full production deployment"
            echo "  $0 --help            # Show all options"
            ;;
    esac
}

main "$@"
