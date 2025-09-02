# End-to-End Encrypted Chat Application

Secure messaging with post-quantum cryptography and Signal Protocol integration.

## Quick Start

### Automated Installation (Recommended)

**Cross-platform installer that handles all dependencies:**

```bash
git clone https://github.com/galacticoder/end2end-chat-site.git
cd end2end-chat-site
./install-dependencies.sh
```

**Supported platforms:**
- **Linux**: Ubuntu/Debian, Fedora/RHEL, Arch Linux
- **macOS**: Intel and Apple Silicon
- **Windows**: Git Bash, WSL, or similar Unix-like environment

The installer will:
- Install Node.js, pnpm, and system dependencies
- Configure Tor for secure networking
- Set up Electron dependencies
- Install project dependencies
- Create desktop shortcuts

### Manual Setup

#### Option 1: Electron Desktop App (Recommended)

**Prerequisites:**
- Node.js 18+ and pnpm
- System dependencies (see install-dependencies.sh)

**Installation:**
1. **Clone and setup:**
   ```bash
   git clone https://github.com/galacticoder/end2end-chat-site.git
   cd end2end-chat-site
   ```

2. **Start the application:**
   ```bash
   ./startClient.sh  # Launches Electron app + dev server
   ./startServer.sh  # In another terminal for backend
   ```

#### Option 2: Server in Docker + Local Client

**Best for development - isolated server, native Electron client:**

1. **Start server in Docker:**
   ```bash
   ./setup_chat_docker.sh  # Choose option 1 (Server only)
   ```

2. **Start client locally:**
   ```bash
   ./startClient.sh  # Native Electron app
   ```

## Features

### Communication
- Real-time messaging with typing indicators
- Secure file sharing with chunked encryption
- Voice and video calls with WebRTC
- Screen sharing with quality controls
- Message replies and threading
- Offline message delivery

### Privacy & Security
- End-to-end encryption with Signal Protocol
- Post-quantum cryptography (Kyber768, Dilithium3)
- Tor network integration for anonymity
- Zero-knowledge server architecture
- Rate limiting and spam protection
- Multi-layer authentication

### Platform Support
- Cross-platform desktop apps (Electron)

## Security Implementation

### Encryption
- **Signal Protocol:** Double Ratchet algorithm with X3DH key agreement
- **Post-Quantum:** Kyber768 key encapsulation, Dilithium3 signatures
- **Symmetric:** XChaCha20-Poly1305, ChaCha20-Poly1305, AES-256-GCM
- **Hashing:** BLAKE3, Argon2id for passwords, HKDF-SHA512

### Privacy Features
- Zero-knowledge server design
- Local encrypted storage (IndexedDB)
- Optional Tor routing
- Minimal metadata collection
- Perfect forward secrecy

## Technology Stack

### Frontend
- React 18 with TypeScript
- Vite build system
- Tailwind CSS + shadcn/ui
- Electron for desktop apps

### Backend
- Node.js with WebSocket server
- SQLite/PostgreSQL database
- Self-signed TLS certificates
- Redis support for scaling

### Cryptography Libraries
- @noble/post-quantum (Kyber, Dilithium)
- @noble/ciphers (ChaCha20, XChaCha20)
- @noble/hashes (BLAKE3)
- argon2-wasm
- Signal Protocol implementation

## Configuration

### Docker Configuration

**Environment Variables for Docker:**
```bash
# Create a .env file for custom configuration
DB_BACKEND=sqlite|postgres
DATABASE_URL=<connection_string>
SERVER_PASSWORD=<password>
RATE_LIMIT_ENABLED=true
TOR_ENABLED=false
```

## Docker Usage (Server Only)

**Docker is used only for the server component. The client (Electron app) runs natively for the best user experience.**

### Quick Server Setup

```bash
# Automated server setup with Docker
./setup_chat_docker.sh

# Choose option 1: Run Server (Backend - Node.js) in Docker
# This will build and run the server in an isolated container
```

### Manual Docker Commands

```bash
# Build server image
docker build -t end2end-chat-server .

# Run server container
docker run -it --rm \
  --name chat-server \
  -p 8080:8080 \
  -p 8443:8443 \
  end2end-chat-server

# View server logs
docker logs chat-server

# Clean up
./setup_chat_docker.sh  # Choose option 2 (Cleanup)
```

### Why Docker for Server Only?

- **Server**: Benefits from containerization (isolation, consistent environment, easy deployment)
- **Client**: Electron apps work best natively (GUI access, system integration, performance)

### Server Setup (No need to do this as is already handled by server script unless you want to do it manually)
```bash
# Environment Variables
DB_BACKEND=sqlite|postgres
DATABASE_URL=<connection_string>
SERVER_PASSWORD=<password>
RATE_LIMIT_ENABLED=true
TOR_ENABLED=false
```

### Development
```bash
# Install dependencies
pnpm install

# Development mode
pnpm run dev

# Production build
pnpm run build

# Electron build
pnpm run build:electron
```

## Security Highlights

### Network Security
- TLS 1.3 with certificate pinning
- Encrypted WebSocket connections
- Optional Tor routing with circuit rotation
- Rate limiting and DDoS protection

### Data Protection
- No plaintext storage on server
- Encrypted local database (IndexedDB)
- Automatic secure deletion
- Minimal metadata collection

### Open Source & Auditable
- Full source code available for review
- Regular security audits
- TypeScript for type safety
- Automated testing and static analysis

## License

MIT License - see LICENSE file for details.

## Have an idea or request?

Found a bug or have a feature request? Open an issue [here](https://github.com/galacticoder/end2end-chat-site/issues).
