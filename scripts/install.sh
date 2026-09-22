#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$HOME/.local/bin"
LOG_DIR="$HOME/Library/Logs/secrets"
LAUNCH_AGENTS_DIR="$HOME/Library/LaunchAgents"
LABEL="dev.pawel.secretsd"
PLIST_PATH="$LAUNCH_AGENTS_DIR/$LABEL.plist"

echo "Building release binary..."
cd "$REPO_DIR"
swift build -c release

mkdir -p "$BIN_DIR" "$LOG_DIR" "$LAUNCH_AGENTS_DIR"
cp "$REPO_DIR/.build/release/secrets" "$BIN_DIR/secrets"
chmod 755 "$BIN_DIR/secrets"

sed -e "s|__BIN_PATH__|$BIN_DIR/secrets|g" -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$REPO_DIR/LaunchAgents/$LABEL.plist" > "$PLIST_PATH"

launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"

echo
echo "Installed."
echo "  binary:      $BIN_DIR/secrets"
echo "  launchagent: $PLIST_PATH"
echo "  logs:        $LOG_DIR"
echo
echo "Make sure $BIN_DIR is on your PATH (it already is if you use ~/.local/bin for other tools)."
echo "Run 'secrets unlock' once to authorize this Claude/terminal session with Touch ID."
