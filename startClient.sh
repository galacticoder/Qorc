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
pnpm install

# Prevent auto-opening external browser and enable Electron DevTools
export BROWSER=none
export ELECTRON_OPEN_DEVTOOLS=1

# Ensure Vite uses fixed port and won't open
export VITE_PORT=5173

START_ELECTRON="${START_ELECTRON:-1}"

if [ "$START_ELECTRON" = "1" ]; then
    echo -e "${GREEN}Starting client application (Vite + Electron)...${NC}"
    pnpm run dev &
else
    echo -e "${GREEN}Starting client application (Vite only; no window). Set START_ELECTRON=1 to launch Electron.${NC}"
    pnpm run vite &
fi

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