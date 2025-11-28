#!/bin/sh
set -e

echo "[REDIS-ENTRYPOINT] Starting Redis TLS setup..."

# Check if certificates exist in the mounted volume
if [ ! -f /certs/redis-ca.crt ] || [ ! -f /certs/redis.crt ] || [ ! -f /certs/redis-client.crt ]; then
  echo "[REDIS-ENTRYPOINT] Generating TLS certificates..."
  
  # Generate CA certificate
  openssl genrsa -out /certs/redis-ca.key 4096
  openssl req -new -x509 -days 3650 -key /certs/redis-ca.key \
    -out /certs/redis-ca.crt -subj "/CN=Redis-CA"
  
  # Generate Redis server certificate with SANs
  openssl genrsa -out /certs/redis.key 4096
  openssl req -new -key /certs/redis.key \
    -out /certs/redis.csr -subj "/CN=redis"

# Create SANs config
cat > /certs/redis-san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = redis
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -days 3650 \
  -in /certs/redis.csr -CA /certs/redis-ca.crt -CAkey /certs/redis-ca.key \
  -CAcreateserial -out /certs/redis.crt \
  -extensions v3_req -extfile /certs/redis-san.cnf
  
  # Generate client certificate
  openssl genrsa -out /certs/redis-client.key 4096
  openssl req -new -key /certs/redis-client.key \
    -out /certs/redis-client.csr -subj "/CN=redis-client"
  openssl x509 -req -days 3650 \
    -in /certs/redis-client.csr -CA /certs/redis-ca.crt -CAkey /certs/redis-ca.key \
    -CAcreateserial -out /certs/redis-client.crt
  
  chmod 644 /certs/redis.crt /certs/redis-ca.crt /certs/redis-client.crt
  chmod 600 /certs/redis.key /certs/redis-client.key /certs/redis-ca.key
  chown -R redis:redis /certs
  
  echo "[REDIS-ENTRYPOINT] TLS certificates generated successfully"
else
  echo "[REDIS-ENTRYPOINT] Using existing TLS certificates"
fi

echo "[REDIS-ENTRYPOINT] Starting Redis with TLS..."
exec redis-server \
  --requirepass "${REDIS_PASSWORD}" \
  --tls-port 6379 \
  --port 0 \
  --tls-cert-file /certs/redis.crt \
  --tls-key-file /certs/redis.key \
  --tls-ca-cert-file /certs/redis-ca.crt \
  --tls-auth-clients yes \
  --bind 0.0.0.0 \
  --protected-mode no \
  --daemonize no
