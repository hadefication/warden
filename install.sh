#!/bin/sh
# warden installer — builds from source and installs to ~/.local/bin.
#
#   ./install.sh
#
set -eu

INSTALL_DIR="${WARDEN_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo dev)"

err() { printf 'warden-install: %s\n' "$1" >&2; exit 1; }

command -v go >/dev/null 2>&1 || err "go is required"

mkdir -p "$INSTALL_DIR"
go build -ldflags "-X github.com/hadefication/warden/internal/mcpserver.version=$VERSION" \
	-o "$INSTALL_DIR/warden" ./cmd/warden

printf 'warden %s installed to %s\n' "$VERSION" "$INSTALL_DIR/warden"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) printf 'note: %s is not on your PATH\n' "$INSTALL_DIR" ;;
esac
