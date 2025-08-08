#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat server        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"

cd "$(dirname "$0")"

if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Node.js is not installed. Please install Node.js to run the server.${NC}"
    exit 1
fi

echo -e "${GREEN}Installing WebSocket server dependencies...${NC}"
npm install

echo -e "${GREEN}Starting secure WebSocket server...${NC}"
node server/server.js

cleanup() {
    echo -e "${YELLOW}Shutting down server...${NC}"
    kill $SERVER_PID 2>/dev/null
    reset
    exit
}

trap cleanup INT TERM


echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}end2end server is now running!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop server${NC}"

wait
