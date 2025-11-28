#!/bin/bash
set -e

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
        if su - postgres -c "$PSQL -l" >/dev/null 2>&1; then
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

echo "Starting Postgres with SSL..."
exec su - postgres -c "$PG_BIN -D $PGDATA -c ssl=on -c ssl_cert_file=/var/lib/postgresql/certs/server.crt -c ssl_key_file=/var/lib/postgresql/certs/server.key"
