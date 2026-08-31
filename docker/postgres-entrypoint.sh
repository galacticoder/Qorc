#!/bin/bash
set -e

if [ -z "${POSTGRES_PASSWORD:-}" ]; then
  echo "POSTGRES_PASSWORD is required" >&2
  exit 1
fi

POSTGRES_DB="${POSTGRES_DB:-qorc}"
PG_ALLOWED_CIDR="${PG_ALLOWED_CIDR:-172.16.0.0/12}"
if ! [[ "$POSTGRES_DB" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]]; then
  echo "POSTGRES_DB must be a simple PostgreSQL identifier" >&2
  exit 1
fi
if ! [[ "$PG_ALLOWED_CIDR" =~ ^[0-9a-fA-F:.]+/[0-9]{1,3}$ ]]; then
  echo "PG_ALLOWED_CIDR is invalid" >&2
  exit 1
fi

echo "[POSTGRES-ENTRYPOINT] Starting Postgres TLS setup..."

CERT_DIR="/var/lib/postgresql/certs"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ] || [ ! -f "$CERT_DIR/root.crt" ]; then
  echo "[POSTGRES-ENTRYPOINT] Generating TLS certificates..."
  
  # Generate CA certificate
  openssl genrsa -out "$CERT_DIR/root.key" 4096
  openssl req -new -x509 -days 3650 -key "$CERT_DIR/root.key" \
    -out "$CERT_DIR/root.crt" -subj "/CN=Postgres-CA"
  
  # Generate server certificate
  openssl genrsa -out "$CERT_DIR/server.key" 4096
  openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -subj "/CN=postgres" \
    -addext "subjectAltName=DNS:postgres"
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
CREATEDB="/usr/lib/postgresql/$PG_VERSION/bin/createdb"
PGDATA="/var/lib/postgresql/data"

if [ ! -d "$PGDATA" ]; then
    mkdir -p "$PGDATA"
fi

chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

# Initialize database if empty
if [ -z "$(ls -A "$PGDATA")" ]; then
    echo "Initializing database..."
    runuser -u postgres -- "$INITDB" -D "$PGDATA" --auth-local=peer --auth-host=scram-sha-256

    echo "listen_addresses='*'" >> "$PGDATA/postgresql.conf"
    echo "password_encryption='scram-sha-256'" >> "$PGDATA/postgresql.conf"
    
    echo "Starting Postgres temporarily to set password..."
    runuser -u postgres -- "$PG_BIN" -D "$PGDATA" -c listen_addresses=localhost &
    PID=$!
    
    for i in {1..30}; do
        if runuser -u postgres -- "$PSQL" -l > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    echo "Setting postgres user password..."
    printf '%s\n' "ALTER ROLE postgres PASSWORD :'password';" | \
      runuser -u postgres -- "$PSQL" -v "password=$POSTGRES_PASSWORD" -d postgres
    
    if [ "$POSTGRES_DB" != "postgres" ]; then
        echo "Creating database $POSTGRES_DB..."
        runuser -u postgres -- "$CREATEDB" "$POSTGRES_DB"
    fi
    
    echo "Stopping temporary Postgres..."
    kill $PID
    wait $PID
fi

cat > "$PGDATA/pg_hba.conf" <<EOF
local all all peer
hostssl all all 127.0.0.1/32 scram-sha-256
hostssl all all ::1/128 scram-sha-256
hostssl all all ${PG_ALLOWED_CIDR} scram-sha-256
EOF
chown postgres:postgres "$PGDATA/pg_hba.conf"
chmod 600 "$PGDATA/pg_hba.conf"

echo "[POSTGRES-ENTRYPOINT] Starting Postgres with TLS..."
exec runuser -u postgres -- "$PG_BIN" -D "$PGDATA" \
  -c ssl=on \
  -c "ssl_cert_file=$CERT_DIR/server.crt" \
  -c "ssl_key_file=$CERT_DIR/server.key" \
  -c "ssl_ca_file=$CERT_DIR/root.crt"
