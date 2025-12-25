#!/bin/bash
set -e

if [ -z "$TURN_EXTERNAL_IP" ]; then
    echo "[TURN] Detecting external IP..."
    
    detect_ipv4() {
        if command -v hostname >/dev/null 2>&1; then
             local all_ips=$(hostname -I 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
             
             # Prioritize Tailscale IP
             local tailscale_ip=$(echo "$all_ips" | grep -oE '\b100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b' | head -n 1)
             if [ -n "$tailscale_ip" ]; then
                 echo "$tailscale_ip"
                 return
             fi

             # Return first IPv4 found
             local first_ip=$(echo "$all_ips" | head -n 1)
             if [ -n "$first_ip" ]; then
                 echo "$first_ip"
                 return
             fi
        fi

        curl -4 -sf https://ifconfig.me || curl -4 -sf https://api.ipify.org || curl -4 -sf https://icanhazip.com || echo ""
    }

    TURN_EXTERNAL_IP=$(detect_ipv4)

    if [ -z "$TURN_EXTERNAL_IP" ]; then
        echo "[TURN] WARNING: Could not detect external IP. TURN may not work correctly."
        echo "[TURN] Set TURN_EXTERNAL_IP in your .env file for reliable operation."
        TURN_EXTERNAL_IP="0.0.0.0"
    else
        echo "[TURN] Detected external IP: $TURN_EXTERNAL_IP"
    fi
fi

TURN_PORT=${TURN_PORT:-3478}
TURNS_PORT=${TURNS_PORT:-5349}
TURN_REALM=${TURN_REALM:-turn.local}
TURN_USERNAME=${TURN_USERNAME:-turnuser}
TURN_PASSWORD=${TURN_PASSWORD:-turnpassword}
TURN_MIN_PORT=${TURN_MIN_PORT:-49152}
TURN_MAX_PORT=${TURN_MAX_PORT:-65535}

echo "[TURN] Starting coturn TURN server..."
echo "[TURN] External IP: $TURN_EXTERNAL_IP"
echo "[TURN] TURN Port: $TURN_PORT"
echo "[TURN] TURNS Port: $TURNS_PORT"
echo "[TURN] Realm: $TURN_REALM"
echo "[TURN] Username: $TURN_USERNAME"
echo "[TURN] Relay ports: $TURN_MIN_PORT-$TURN_MAX_PORT"

# Generate turnserver.conf
cat > /etc/turnserver/turnserver.conf << EOF
# Network settings
listening-port=$TURN_PORT
tls-listening-port=$TURNS_PORT
fingerprint
lt-cred-mech
listening-ip=0.0.0.0

relay-ip=$TURN_EXTERNAL_IP
external-ip=$TURN_EXTERNAL_IP

# Realm
realm=$TURN_REALM
server-name=$TURN_REALM

# Static user credentials
user=$TURN_USERNAME:$TURN_PASSWORD

# Relay port range
min-port=$TURN_MIN_PORT
max-port=$TURN_MAX_PORT

# Performance settings
total-quota=100
bps-capacity=0
stale-nonce=600
no-multicast-peers

# Logging
log-file=/var/log/turnserver/turnserver.log
simple-log
verbose

denied-peer-ip=10.0.0.0-10.255.255.255
denied-peer-ip=172.16.0.0-172.31.255.255
denied-peer-ip=192.168.0.0-192.168.255.255
denied-peer-ip=127.0.0.0-127.255.255.255

# Allow Tailscale CGNAT range (100.64.0.0/10)
allowed-peer-ip=100.64.0.0-100.127.255.255

# Allow local network for testing (192.168.x.x)
allowed-peer-ip=192.168.0.0-192.168.255.255

# Allow localhost for internal testing
allowed-peer-ip=127.0.0.1

# No CLI admin interface
no-cli
EOF

# Auto-detect TLS certs if not provided
if [ -z "$TURN_TLS_CERT" ] && [ -d "/app/certs" ]; then
    for cert in /app/certs/*.crt; do
        [ -e "$cert" ] || continue
        base="${cert%.crt}"
        if [ -e "${base}.key" ]; then
            echo "[TURN] Auto-detected TLS cert/key pair: $cert"
            TURN_TLS_CERT="$cert"
            TURN_TLS_KEY="${base}.key"
            break
        fi
    done
fi

# Add TLS certs if provided
if [ -n "$TURN_TLS_CERT" ] && [ -f "$TURN_TLS_CERT" ]; then
    echo "cert=$TURN_TLS_CERT" >> /etc/turnserver/turnserver.conf
fi
if [ -n "$TURN_TLS_KEY" ] && [ -f "$TURN_TLS_KEY" ]; then
    echo "pkey=$TURN_TLS_KEY" >> /etc/turnserver/turnserver.conf
fi

echo "[TURN] Configuration written to /etc/turnserver/turnserver.conf"
exec turnserver -c /etc/turnserver/turnserver.conf --no-cli -v
