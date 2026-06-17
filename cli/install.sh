#!/usr/bin/env bash
# Install preflight CLI — curl -sSL https://preflight.lol/install.sh | bash
set -euo pipefail

REPO="yokedotlol/preflight"

echo "Installing preflight..."

# Detect OS/arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "error: unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

# Get latest release tag
LATEST=$(curl -sfL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
if [ -z "$LATEST" ]; then
  echo "error: could not determine latest release" >&2; exit 1
fi

echo "  Version: $LATEST ($OS/$ARCH)"

# Build download URL
EXT="tar.gz"
[ "$OS" = "windows" ] && EXT="zip"
URL="https://github.com/$REPO/releases/download/$LATEST/preflight_${OS}_${ARCH}.${EXT}"

# Download and extract
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "  Downloading..."
curl -sfL "$URL" -o "$TMP/archive.$EXT"

echo "  Extracting..."
if [ "$EXT" = "zip" ]; then
  unzip -q "$TMP/archive.zip" -d "$TMP"
else
  tar -xzf "$TMP/archive.tar.gz" -C "$TMP"
fi

# Install
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  echo "  Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "$TMP/preflight" "$INSTALL_DIR/preflight"
else
  mv "$TMP/preflight" "$INSTALL_DIR/preflight"
fi
chmod +x "$INSTALL_DIR/preflight"

echo "  ✓ Installed preflight $LATEST to $INSTALL_DIR/preflight"
echo ""
echo "  Usage: preflight example.com"
