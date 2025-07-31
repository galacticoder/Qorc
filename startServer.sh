#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        SecureChat - Secure Messaging       ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Node.js is not installed. Please install Node.js to run the server.${NC}"
    exit 1
fi

if ! command -v pnpm &> /dev/null; then
    echo -e "${YELLOW}pnpm is not installed. Installing pnpm using npm...${NC}"
    if ! command -v npm &> /dev/null; then
      echo -e "${YELLOW}npm is not installed. Please install npm to install pnpm.${NC}"
      exit 1
    fi
    npm install -g pnpm
    if ! command -v pnpm &> /dev/null; then
      echo -e "${YELLOW}Failed to install pnpm. Please install it manually.${NC}"
      exit 1
    fi
    USE_NPM=false
else
    USE_NPM=false
fi

echo -e "${GREEN}Installing WebSocket server dependencies...${NC}"
cd server
npm install

echo -e "${GREEN}Starting secure WebSocket server...${NC}"
node server.js

cleanup() {
    echo -e "${YELLOW}Shutting down server...${NC}"
    kill $SERVER_PID 2>/dev/null
    reset
    exit
}

trap cleanup INT TERM


echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}SecureChat is now running!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop server${NC}"

wait
