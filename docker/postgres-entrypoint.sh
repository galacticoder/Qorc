#!/bin/bash
set -e

echo "[POSTGRES-ENTRYPOINT] Starting Postgres TLS setup..."

CERT_DIR="/var/lib/postgresql/certs"
mkdir -p "$CERT_DIR"

# Check if certificates exist
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ] || [ ! -f "$CERT_DIR/root.crt" ]; then
  echo "[POSTGRES-ENTRYPOINT] Generating TLS certificates..."
  
  # Generate CA certificate
  openssl genrsa -out "$CERT_DIR/root.key" 4096
  openssl req -new -x509 -days 3650 -key "$CERT_DIR/root.key" \
    -out "$CERT_DIR/root.crt" -subj "/CN=Postgres-CA"
  
  # Generate server certificate
  openssl genrsa -out "$CERT_DIR/server.key" 4096
  openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -subj "/CN=postgres"
  openssl x509 -req -days 3650 \
    -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/root.crt" -CAkey "$CERT_DIR/root.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt"
  
  chmod 600 "$CERT_DIR/server.key" "$CERT_DIR/root.key"
  chmod 644 "$CERT_DIR/server.crt" "$CERT_DIR/root.crt"
  chown -R postgres:postgres "$CERT_DIR"
  
  echo "[POSTGRES-ENTRYPOINT] TLS certificates generated successfully"
else
  echo "[POSTGRES-ENTRYPOINT] Using existing TLS certificates"
fi

PG_VERSION=$(ls /usr/lib/postgresql/ | sort -V | tail -n 1)
if [ -z "$PG_VERSION" ]; then
    echo "Postgres not found!"
    exit 1
fi

PG_BIN="/usr/lib/postgresql/$PG_VERSION/bin/postgres"
INITDB="/usr/lib/postgresql/$PG_VERSION/bin/initdb"
PSQL="/usr/lib/postgresql/$PG_VERSION/bin/psql"
PGDATA="/var/lib/postgresql/data"

if [ ! -d "$PGDATA" ]; then
    mkdir -p "$PGDATA"
fi

chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Initialize database if empty
if [ -z "$(ls -A "$PGDATA")" ]; then
    echo "Initializing database..."
    su - postgres -c "$INITDB -D $PGDATA"

    echo "host all all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
    echo "hostssl all all 0.0.0.0/0 md5" >> "$PGDATA/pg_hba.conf"
    echo "listen_addresses='*'" >> "$PGDATA/postgresql.conf"
    
    echo "Starting Postgres temporarily to set password..."
    su - postgres -c "$PG_BIN -D $PGDATA -c listen_addresses='localhost'" &
    PID=$!
    
    for i in {1..30}; do
        if su - postgres -c "$PSQL -l" > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    if [ -n "$POSTGRES_PASSWORD" ]; then
        echo "Setting postgres user password..."
        su - postgres -c "$PSQL -c \"ALTER USER postgres WITH PASSWORD '$POSTGRES_PASSWORD';\""
    fi
    
    echo "Stopping temporary Postgres..."
    kill $PID
    wait $PID
fi

echo "[POSTGRES-ENTRYPOINT] Starting Postgres with TLS..."
exec su - postgres -c "$PG_BIN -D $PGDATA -c ssl=on -c ssl_cert_file=$CERT_DIR/server.crt -c ssl_key_file=$CERT_DIR/server.key -c ssl_ca_file=$CERT_DIR/root.crt"
