# Server Dockerfile - Backend only
FROM node:20-bullseye-slim

# Install system dependencies including Redis and build tools
RUN apt-get update && apt-get install -y \
    dumb-init \
    sudo \
    curl \
    redis-server \
    build-essential \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app user for security
RUN groupadd --gid 1001 nodejs && \
    useradd --uid 1001 --gid nodejs --shell /bin/bash --create-home nodejs \
    && echo "nodejs ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Node.js and pnpm as root (better caching)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g pnpm@8.10.0

# Set working directory and copy package files first
WORKDIR /app
COPY config/package.json config/pnpm-lock.yaml ./
COPY server/package*.json ./server/

# Install main project dependencies at root level (so server can find them)
RUN pnpm install --frozen-lockfile --prod && \
    cd server && npm install --only=production && cd ..

# Copy only the source files we need (exclude node_modules)
COPY --chown=nodejs:nodejs server/ ./server/
COPY --chown=nodejs:nodejs src/ ./src/
COPY --chown=nodejs:nodejs startServer.sh ./
# COPY --chown=nodejs:nodejs README.md ./
COPY --chown=nodejs:nodejs index.html ./
COPY --chown=nodejs:nodejs server/package.json ./package.json

# Make scripts executable
RUN chmod +x startServer.sh

# Switch to nodejs user
USER nodejs
ENV HOME=/home/nodejs

# Set environment variables for Docker environment
ENV SKIP_INSTALL=1
ENV SKIP_REBUILD=1
ENV DISABLE_CONNECTION_LIMIT=true
ENV REDIS_URL=redis://127.0.0.1:6379

# Expose ports for HTTP and HTTPS
EXPOSE 8080 8443

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start Redis in background and then start the server
CMD ["sh", "-c", "redis-server --daemonize yes --bind 127.0.0.1 --port 6379 && ./startServer.sh"]
