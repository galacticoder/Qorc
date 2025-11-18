#!/bin/bash
set -euo pipefail

OS="$(uname -s)" ARCH="$(uname -m)"
RED='\033[0;31m' GREEN='\033[0;32m' BLUE='\033[0;34m' YELLOW='\033[1;33m' NC='\033[0m'

[[ "$OS" == "Darwin" ]] && {
    export HOMEBREW_NO_EMOJI=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1
    export PATH="$([[ "$ARCH" == "arm64" ]] && echo "/opt/homebrew" || echo "/usr/local")/bin:$PATH"
}

[[ "${1:-}" =~ ^(-h|--help)$ ]] && { echo "Usage: $0 - Starts end2end chat client"; exit 0; }

echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${GREEN}        end2end chat client        ${BLUE}║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
cd "$(dirname "$0")"

detect_pkg_mgr() {
    for mgr in apt-get dnf yum pacman zypper apk xbps-install emerge eopkg swupd nix-env brew; do
        command -v $mgr &>/dev/null && { echo $mgr; return; }
    done
}

PKG_MGR=$(detect_pkg_mgr)

install_pkg() {
    case "$PKG_MGR" in
        apt-get) sudo apt-get update && sudo apt-get install -y $@ ;;
        dnf) sudo dnf install -y $@ ;;
        yum) sudo yum install -y $@ ;;
        pacman) sudo pacman -Sy --noconfirm && sudo pacman -S --noconfirm $@ ;;
        zypper) sudo zypper refresh && sudo zypper install -y $@ ;;
        apk) sudo apk add --no-cache $@ ;;
        xbps-install) sudo xbps-install -S $@ ;;
        emerge) sudo emerge --ask=n $@ ;;
        eopkg) sudo eopkg install -y $@ ;;
        swupd) sudo swupd bundle-add $@ ;;
        nix-env) nix-env -iA $(printf "nixpkgs.%s " $@) ;;
        brew) brew install --quiet $@ 2>/dev/null || brew install $@ ;;
    esac
}

for tool in curl wget git; do
    command -v $tool &>/dev/null || install_pkg $tool
done

install_nodejs() {
    [[ "$PKG_MGR" =~ ^(apt-get|dnf|yum)$ ]] && \
        curl -fsSL https://$([ "$PKG_MGR" = "apt-get" ] && echo "deb" || echo "rpm").nodesource.com/setup_lts.x | sudo bash -
    install_pkg nodejs npm
}

if ! command -v node &>/dev/null || [ $(node --version 2>/dev/null | sed 's/v//' | cut -d. -f1) -lt 18 ]; then
    install_nodejs
fi


check_and_install_tor_deps() {
    case "$PKG_MGR" in
        apt-get) 
            dpkg -l libevent-2.1-7t64 2>/dev/null | grep -q ^ii || \
            dpkg -l libevent-2.1-7 2>/dev/null | grep -q ^ii || \
            install_pkg libevent-2.1-7t64 || install_pkg libevent-2.1-7 ;;
        dnf|yum) rpm -q libevent &>/dev/null || install_pkg libevent ;;
        pacman) pacman -Q libevent &>/dev/null || install_pkg libevent ;;
        zypper) rpm -q libevent &>/dev/null || install_pkg libevent ;;
        apk) apk info -e libevent &>/dev/null || install_pkg libevent ;;
        brew) brew list libevent &>/dev/null || install_pkg libevent ;;
    esac 2>/dev/null || true
}
check_and_install_tor_deps

for f in package.json pnpm-lock.yaml postcss.config.js tailwind.config.ts vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json; do
    [ ! -L "$f" ] && ln -sf config/$f $f
done

export PATH="$([[ "$OS" == "Darwin" ]] && echo "$([[ "$ARCH" == "arm64" ]] && echo "/opt/homebrew" || echo "/usr/local")/opt/curl/bin:" || echo "")/usr/local/bin:$HOME/.local/bin:$HOME/.local/share/pnpm:$PATH"

install_pnpm() {
    local bin_dir="$([[ "$OS" == "Darwin" ]] && echo "$([[ "$ARCH" == "arm64" ]] && echo "/opt/homebrew" || echo "/usr/local")" || echo "/usr/local")/bin"
    local pnpm_url="https://github.com/pnpm/pnpm/releases/latest/download/pnpm-$([[ "$OS" == "Darwin" ]] && echo "macos-$([[ "$ARCH" == "arm64" ]] && echo "arm64" || echo "x64")" || echo "linuxstatic-x64")"
    
    sudo corepack enable pnpm 2>/dev/null || \
    sudo npm install -g pnpm --no-audit --no-fund 2>/dev/null || \
    { sudo mkdir -p $bin_dir && curl -fsSL $pnpm_url -o /tmp/pnpm && sudo mv /tmp/pnpm $bin_dir/pnpm && sudo chmod +x $bin_dir/pnpm; }
}

command -v pnpm >/dev/null 2>&1 || { install_pnpm && command -v pnpm >/dev/null || { echo -e "${RED}pnpm install failed${NC}"; exit 1; }; }

[ ! -d node_modules ] || [ config/pnpm-lock.yaml -nt node_modules/.modules.yaml ] && pnpm install --prefer-offline

for pkg in "@tailwindcss/aspect-ratio" tailwindcss autoprefixer "@vitejs/plugin-react" vite electron typescript; do
    node -e "require.resolve('${pkg}')" 2>/dev/null || { pnpm install; break; }
done

node -e "require('electron')" 2>/dev/null || {
    node $(node -e "console.log(require.resolve('electron/install.js'))" 2>/dev/null) 2>/dev/null || pnpm add -D electron@latest
}

rebuild_electron_natives() {
    local electron_ver=$(node -e "console.log(require('electron/package.json').version)" 2>/dev/null)
    [ -z "$electron_ver" ] && return 0
    [ -f ".cache/rebuilt-electron-natives-${electron_ver}" ] && [ -z "${FORCE_ELECTRON_REBUILD:-}" ] && return 0
    
    mkdir -p .cache
    [ "$PKG_MGR" = "apt-get" ] && sudo apt-get install -y build-essential python3 2>/dev/null || true
    command -v cargo >/dev/null || { curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source "$HOME/.cargo/env"; }
    
    node -e "require.resolve('@electron/rebuild')" 2>/dev/null || pnpm add -D @electron/rebuild
    
    local mods=()
    node -e "require.resolve('@signalapp/libsignal-client')" 2>/dev/null && mods+=("@signalapp/libsignal-client")
    
    [ ${#mods[@]} -gt 0 ] && {
        pnpm exec electron-rebuild --version "${electron_ver}" -f -w "$(IFS=,; echo "${mods[*]}")" && touch ".cache/rebuilt-electron-natives-${electron_ver}"
    }
}

rebuild_electron_natives || { echo -e "${YELLOW}Native rebuild failed. Try: FORCE_ELECTRON_REBUILD=1 ./startClient.sh${NC}"; exit 1; }

[ -f "$(pnpm root 2>/dev/null)/electron/dist/chrome-sandbox" ] && \
    sudo chown root:root "$(pnpm root)/electron/dist/chrome-sandbox" 2>/dev/null && \
    sudo chmod 4755 "$(pnpm root)/electron/dist/chrome-sandbox" 2>/dev/null || true

export VITE_PORT=5173
{ lsof -t -i TCP:5173 -sTCP:LISTEN 2>/dev/null | xargs -r kill -9 2>/dev/null; } || \
{ fuser -k 5173/tcp 2>/dev/null; } || true

cleanup_and_retry() {
    rm -rf node_modules pnpm-lock.yaml package-lock.json
    [ -f config/pnpm-lock.yaml ] && ln -sf config/pnpm-lock.yaml pnpm-lock.yaml
    pnpm install && exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/startClient.sh" "$@"
}

START_ELECTRON="${START_ELECTRON:-1}"

cleanup() { [ -n "${CLIENT_PID:-}" ] && kill -0 "$CLIENT_PID" 2>/dev/null && { kill "$CLIENT_PID" 2>/dev/null; wait "$CLIENT_PID" 2>/dev/null; }; exit; }
trap cleanup INT TERM

if [ "$START_ELECTRON" = "1" ]; then
    pnpm exec vite & VITE_PID=$!
    pnpm exec wait-on "http://localhost:${VITE_PORT}" || { kill "$VITE_PID" 2>/dev/null; [ ! -f /tmp/client_retry_attempted ] && { touch /tmp/client_retry_attempted; cleanup_and_retry; } || exit 1; }
    ./node_modules/.bin/electron .
    EC=$? && kill "$VITE_PID" 2>/dev/null && rm -f /tmp/client_retry_attempted 2>/dev/null && exit $EC
else
    pnpm run vite 2>&1 | tee /tmp/client_output.log || { grep -qE "(ERR_|MODULE_NOT_FOUND|Cannot find)" /tmp/client_output.log && [ ! -f /tmp/client_retry_attempted ] && { touch /tmp/client_retry_attempted; cleanup_and_retry; } || exit 1; } &
fi

CLIENT_PID=$!
echo -e "${GREEN}end2end client is running! Press Ctrl+C to stop${NC}"
wait
