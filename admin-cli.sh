#!/bin/bash
# Hybrid Post-Quantum Admin CLI
# Manages admin authentication and cluster operations

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_SCRIPT="$SCRIPT_DIR/server/cluster/hybrid-admin-auth.js"
ADMIN_KEYS_FILE="$SCRIPT_DIR/server/config/.cluster-admin-keys.enc"
TOKEN_CACHE="$SCRIPT_DIR/.admin-token-cache"
SERVER_URL="${ADMIN_SERVER_URL:-http://localhost:3000}"

# Helper functions
print_header() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BLUE}Hybrid Post-Quantum Admin CLI${NC}                              ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if admin keys exist
check_keys_exist() {
    if [ ! -f "$ADMIN_KEYS_FILE" ]; then
        return 1
    fi
    return 0
}

# Setup admin credentials
cmd_setup() {
    print_header
    echo -e "${YELLOW}Setting up admin authentication...${NC}"
    echo ""
    
    if check_keys_exist; then
        print_warning "Admin keys already exist at: $ADMIN_KEYS_FILE"
        echo -n "Overwrite existing keys? (yes/no): "
        read -r confirm
        if [ "$confirm" != "yes" ]; then
            print_info "Aborted."
            exit 0
        fi
        rm -f "$ADMIN_KEYS_FILE"
    fi
    
    echo -n "Enter admin username: "
    read -r username
    
    echo -n "Enter admin password (min 16 chars): "
    read -rs password
    echo ""
    
    if [ ${#password} -lt 16 ]; then
        print_error "Password must be at least 16 characters"
        exit 1
    fi
    
    echo ""
    print_info "Generating hybrid keypair..."
    
    node "$AUTH_SCRIPT" setup "$username" "$password"
    
    # Save credentials for token generation
    mkdir -p "$SCRIPT_DIR/.admin"
    echo "$username" > "$SCRIPT_DIR/.admin/username"
    chmod 600 "$SCRIPT_DIR/.admin/username"
    
    print_warning "Password not saved - you'll need to enter it for token generation"
    echo ""
    print_success "Setup complete!"
}

# Generate admin token
cmd_token() {
    print_header
    
    if ! check_keys_exist; then
        print_error "Admin keys not found. Run '$0 setup' first."
        exit 1
    fi
    
    # Try to read cached username
    if [ -f "$SCRIPT_DIR/.admin/username" ]; then
        username=$(cat "$SCRIPT_DIR/.admin/username")
        print_info "Using cached username: $username"
    else
        echo -n "Enter admin username: "
        read -r username
    fi
    
    echo -n "Enter admin password: "
    read -rs password
    echo ""
    echo ""
    
    admin_id="${1:-$username}"
    metadata="${2:-{\"role\":\"admin\"}}"
    
    print_info "Generating admin token..."
    
    token=$(node "$AUTH_SCRIPT" generate "$username" "$password" "$admin_id" "$metadata" 2>/dev/null | grep -A1 "Token:" | tail -1)
    
    if [ -z "$token" ]; then
        print_error "Failed to generate token"
        exit 1
    fi
    
    # Cache token
    echo "$token" > "$TOKEN_CACHE"
    chmod 600 "$TOKEN_CACHE"
    
    echo ""
    print_success "Token generated and cached!"
    echo ""
    echo -e "${CYAN}Token:${NC}"
    echo "$token"
    echo ""
    print_info "Token cached at: $TOKEN_CACHE"
    print_info "Expires in: 1 hour"
    echo ""
    print_info "Use '$0 status' to test the token"
}

# Get cached token
get_token() {
    if [ ! -f "$TOKEN_CACHE" ]; then
        print_error "No cached token found. Run '$0 token' first."
        exit 1
    fi
    cat "$TOKEN_CACHE"
}

# Make API request
api_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    
    token=$(get_token)
    
    if [ -n "$data" ]; then
        response=$(curl -s -X "$method" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$SERVER_URL/api/cluster$endpoint")
    else
        response=$(curl -s -X "$method" \
            -H "Authorization: Bearer $token" \
            "$SERVER_URL/api/cluster$endpoint")
    fi
    
    echo "$response"
}

# Cluster status
cmd_status() {
    print_header
    print_info "Fetching cluster status..."
    echo ""
    
    response=$(api_request "GET" "/status")
    
    # Check if error
    if echo "$response" | grep -q '"success":false'; then
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        print_error "Failed: $error"
        exit 1
    fi
    
    # Pretty print
    echo "$response" | node -e "
        const data = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
        if (data.success && data.cluster) {
            console.log('${CYAN}Cluster Status:${NC}');
            console.log('');
            console.log('Servers:', Object.keys(data.cluster.servers || {}).length);
            console.log('');
            for (const [id, server] of Object.entries(data.cluster.servers || {})) {
                console.log('  ${GREEN}●${NC}', id);
                console.log('    Status:', server.status || 'unknown');
                console.log('    Approved:', server.approved ? '${GREEN}yes${NC}' : '${RED}no${NC}');
                if (server.lastSeen) {
                    const ago = Math.floor((Date.now() - server.lastSeen) / 1000);
                    console.log('    Last seen:', ago < 60 ? ago + 's ago' : Math.floor(ago/60) + 'm ago');
                }
                console.log('');
            }
        } else {
            console.log(JSON.stringify(data, null, 2));
        }
    " 2>/dev/null || echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

# Pending servers
cmd_pending() {
    print_header
    print_info "Fetching pending servers..."
    echo ""
    
    response=$(api_request "GET" "/pending")
    
    if echo "$response" | grep -q '"success":false'; then
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        print_error "Failed: $error"
        exit 1
    fi
    
    echo "$response" | node -e "
        const data = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
        if (data.success && data.pending) {
            if (data.pending.length === 0) {
                console.log('${GREEN}No pending servers${NC}');
            } else {
                console.log('${CYAN}Pending Servers:${NC}');
                console.log('');
                data.pending.forEach((server, i) => {
                    console.log('  ${YELLOW}' + (i+1) + '.${NC}', server.serverId || server.id);
                    if (server.publicKeys) {
                        console.log('     Has public keys');
                    }
                    if (server.requestedAt) {
                        const ago = Math.floor((Date.now() - server.requestedAt) / 1000);
                        console.log('     Requested:', ago < 60 ? ago + 's ago' : Math.floor(ago/60) + 'm ago');
                    }
                    console.log('');
                });
            }
        } else {
            console.log(JSON.stringify(data, null, 2));
        }
    " 2>/dev/null || echo "$response" | jq '.' 2>/dev/null || echo "$response"
}

# Approve server
cmd_approve() {
    if [ -z "$1" ]; then
        print_error "Usage: $0 approve <server-id>"
        exit 1
    fi
    
    server_id="$1"
    
    print_header
    print_info "Approving server: $server_id"
    echo ""
    
    response=$(api_request "POST" "/approve/$server_id")
    
    if echo "$response" | grep -q '"success":true'; then
        print_success "Server approved: $server_id"
    else
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        print_error "Failed: $error"
        exit 1
    fi
}

# Reject server
cmd_reject() {
    if [ -z "$1" ]; then
        print_error "Usage: $0 reject <server-id>"
        exit 1
    fi
    
    server_id="$1"
    
    print_header
    print_info "Rejecting server: $server_id"
    echo ""
    
    response=$(api_request "DELETE" "/reject/$server_id")
    
    if echo "$response" | grep -q '"success":true'; then
        print_success "Server rejected: $server_id"
    else
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        print_error "Failed: $error"
        exit 1
    fi
}

# Remove server
cmd_remove() {
    if [ -z "$1" ]; then
        print_error "Usage: $0 remove <server-id> [reason]"
        exit 1
    fi
    
    server_id="$1"
    reason="${2:-Manual removal}"
    
    print_header
    print_warning "Removing server: $server_id"
    echo ""
    echo -n "Are you sure? (yes/no): "
    read -r confirm
    
    if [ "$confirm" != "yes" ]; then
        print_info "Aborted."
        exit 0
    fi
    
    data="{\"reason\":\"$reason\"}"
    response=$(api_request "DELETE" "/remove/$server_id" "$data")
    
    if echo "$response" | grep -q '"success":true'; then
        print_success "Server removed: $server_id"
    else
        error=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        print_error "Failed: $error"
        exit 1
    fi
}

# Show token info
cmd_info() {
    print_header
    
    if [ ! -f "$TOKEN_CACHE" ]; then
        print_warning "No cached token"
    else
        token=$(cat "$TOKEN_CACHE")
        print_info "Token cached: ${GREEN}Yes${NC}"
        print_info "Token length: ${#token} bytes"
        
        decoded=$(echo "$token" | base64 -d 2>/dev/null | head -c 500 2>/dev/null | strings | head -1)
        if [ -n "$decoded" ]; then
            echo ""
            echo -e "${CYAN}Token Preview:${NC}"
            echo "$decoded" | head -c 200
            echo "..."
        fi
    fi
    
    echo ""
    
    if check_keys_exist; then
        print_info "Admin keys: ${GREEN}Configured${NC}"
        print_info "Keys file: $ADMIN_KEYS_FILE"
    else
        print_warning "Admin keys: ${RED}Not configured${NC}"
        print_info "Run '$0 setup' to configure"
    fi
    
    if [ -f "$SCRIPT_DIR/.admin/username" ]; then
        username=$(cat "$SCRIPT_DIR/.admin/username")
        print_info "Cached username: $username"
    fi
    
    echo ""
    print_info "Server URL: $SERVER_URL"
}

# Clear cached token
cmd_clear() {
    print_header
    
    if [ -f "$TOKEN_CACHE" ]; then
        rm -f "$TOKEN_CACHE"
        print_success "Token cache cleared"
    else
        print_info "No token cache to clear"
    fi
}

# Show usage
cmd_help() {
    print_header
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  ${GREEN}setup${NC}                    Setup admin credentials (first time)"
    echo "  ${GREEN}token${NC} [admin-id]         Generate admin token"
    echo "  ${GREEN}status${NC}                   View cluster status"
    echo "  ${GREEN}pending${NC}                  View pending servers"
    echo "  ${GREEN}approve${NC} <server-id>      Approve a pending server"
    echo "  ${GREEN}reject${NC} <server-id>       Reject a pending server"
    echo "  ${GREEN}remove${NC} <server-id>       Force remove a server"
    echo "  ${GREEN}info${NC}                     Show token and config info"
    echo "  ${GREEN}clear${NC}                    Clear cached token"
    echo "  ${GREEN}help${NC}                     Show this help"
    echo ""
    echo "Environment:"
    echo "  ADMIN_SERVER_URL         Server URL (default: http://localhost:3000)"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 token admin@company.com"
    echo "  $0 status"
    echo "  $0 approve server-xyz"
    echo "  $0 remove server-xyz 'Server compromised'"
    echo ""
    echo "Security:"
    echo "  - Tokens expire after 1 hour"
    echo "  - Password required for each token generation"
    echo "  - Keys encrypted with ML-KEM-1024 + X25519"
    echo "  - Signatures: ML-DSA-87 + Ed25519"
    echo ""
}

# Main
main() {
    command="${1:-help}"
    shift 2>/dev/null || true
    
    case "$command" in
        setup)
            cmd_setup "$@"
            ;;
        token)
            cmd_token "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        pending)
            cmd_pending "$@"
            ;;
        approve)
            cmd_approve "$@"
            ;;
        reject)
            cmd_reject "$@"
            ;;
        remove)
            cmd_remove "$@"
            ;;
        info)
            cmd_info "$@"
            ;;
        clear)
            cmd_clear "$@"
            ;;
        help|--help|-h)
            cmd_help
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            cmd_help
            exit 1
            ;;
    esac
}

main "$@"