#!/usr/bin/env bash
set -euo pipefail

MDBOOK_VERSION=${MDBOOK_VERSION:-0.5.1}
CACHE_DIR="${NETLIFY_CACHE_DIR:-$HOME/.cache}/mdbook/${MDBOOK_VERSION}"
BIN_DIR="$CACHE_DIR/bin"

mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

mkdir -p "$CACHE_DIR/src"
curl -sSL "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
  | tar -xz -C "$CACHE_DIR/src"
mv "$CACHE_DIR/src/mdbook" "$BIN_DIR/mdbook"

mdbook build

if [ "${NOINDEX:-}" = "1" ]; then
  echo "X-Robots-Tag: noindex" > site/_headers
fi
