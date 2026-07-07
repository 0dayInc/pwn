#!/usr/bin/env bash
# Regenerate every PWN data-flow diagram SVG from its .dot source.
# Usage: ./build.sh            # build all
#        ./build.sh foo.dot    # build one
set -euo pipefail
cd "$(dirname "$0")"
DOT_BIN="${DOT_BIN:-dot}"
SRC_DIR="dot"
build_one() {
  local src="$1"
  local base="$(basename "$src" .dot)"
  echo "  [dot] ${base}.svg"
  "$DOT_BIN" -Tsvg "-Gfontnames=svg" "$src" -o "${base}.svg"
}
if [[ $# -gt 0 ]]; then
  for f in "$@"; do build_one "$f"; done
else
  for f in "$SRC_DIR"/*.dot; do build_one "$f"; done
fi
echo "[done] $(ls -1 *.svg | wc -l) SVG diagram(s) in $(pwd)"
