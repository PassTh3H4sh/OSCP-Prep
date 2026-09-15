#!/usr/bin/env bash
# Install oscp-scan as a PATH command (no .py).
# Usage:
#   ./install.sh          # /usr/local/bin if writable, else ~/.local/bin
#   ./install.sh --user   # always ~/.local/bin
#   ./install.sh --system # /usr/local/bin (uses sudo if needed)

set -euo pipefail

HERE="$(cd "$(dirname -- "$0")" && pwd)"
PY="$HERE/oscp-scan.py"
NAME="oscp-scan"

if [[ ! -f "$PY" ]]; then
  echo "missing $PY" >&2
  exit 1
fi

chmod +x "$PY" "$HERE/install.sh" 2>/dev/null || true

write_wrapper() {
  local dest="$1"
  mkdir -p "$(dirname -- "$dest")"
  cat > "$dest" <<EOF
#!/bin/sh
exec /usr/bin/env python3 "$PY" "\$@"
EOF
  chmod +x "$dest"
}

mode="${1:-auto}"
user_bin="${XDG_BIN_HOME:-$HOME/.local/bin}"
system_bin="/usr/local/bin"

case "$mode" in
  --user)
    dest="$user_bin/$NAME"
    write_wrapper "$dest"
    ;;
  --system)
    dest="$system_bin/$NAME"
    if [[ -w "$system_bin" ]]; then
      write_wrapper "$dest"
    else
      tmp="$(mktemp)"
      cat > "$tmp" <<EOF
#!/bin/sh
exec /usr/bin/env python3 "$PY" "\$@"
EOF
      sudo install -m 0755 "$tmp" "$dest"
      rm -f "$tmp"
    fi
    ;;
  auto|"")
    if [[ -w "$system_bin" ]]; then
      dest="$system_bin/$NAME"
      write_wrapper "$dest"
    else
      dest="$user_bin/$NAME"
      write_wrapper "$dest"
    fi
    ;;
  *)
    echo "usage: $0 [--user|--system]" >&2
    exit 1
    ;;
esac

echo "installed $dest"
echo "wrapper -> $PY"

if ! command -v "$NAME" >/dev/null 2>&1; then
  bindir="$(dirname -- "$dest")"
  echo
  echo "not on PATH yet. add this to ~/.zshrc or ~/.bashrc:"
  echo "  export PATH=\"$bindir:\$PATH\""
fi

echo
echo "from a box folder:"
echo "  cd /path/to/OSCP-Prep/boxes/<name>"
echo "  oscp-scan -t TARGET"
