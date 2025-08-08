#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat client        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
cd "$(dirname "$0")"

echo -e "${GREEN}Installing client dependencies...${NC}"
npm install

echo -e "${GREEN}Starting client application...${NC}"

npm run dev &

CLIENT_PID=$!

cleanup() {
    kill $CLIENT_PID 2>/dev/null
    reset
    exit
}

trap cleanup INT TERM

echo -e "${GREEN}==========================================${NC}"
echo -e "${GREEN}end2end client is now running!${NC}"
echo -e "${GREEN}==========================================${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop all processes${NC}"

wait
