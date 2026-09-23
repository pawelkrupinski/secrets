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

# Stop the daemon BEFORE replacing the executable it's running from: overwriting
# a mapped binary in place can crash the running process, and a crash here
# would be mistaken for a bug in the new build.
launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
# Install as a NEW FILE (copy to a temp name, then rename over), never `cp` onto
# the existing path. `cp` rewrites the old inode in place, and on Apple Silicon
# the kernel keeps that inode's code-signature validation cached, so the new
# bytes fail it and every launch is SIGKILLed — launchd reports
# `last exit reason = OS_REASON_CODESIGNING` and the CLI exits 137. A rename
# gives the binary a fresh inode, which is validated from scratch.
cp "$REPO_DIR/.build/release/secrets" "$BIN_DIR/.secrets.new"
chmod 755 "$BIN_DIR/.secrets.new"
# SIGNED WITH A REAL IDENTITY, NOT LEFT AD-HOC. Keychain items trust the code
# identity of the binary that created them; for an ad-hoc build that is the
# exact cdhash, so every rebuild orphaned every item and macOS asked for the
# login password once per item. Signed, the identity is "identifier
# dev.pawel.secrets + this certificate" and the team partition, which survive
# rebuilds (and yearly certificate renewal, since the match is on the name).
IDENTITY="${SECRETS_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)}"
if [ -z "$IDENTITY" ]; then
    echo "No Apple Development signing identity found (set SECRETS_CODESIGN_IDENTITY)." >&2
    exit 1
fi
codesign --force --sign "$IDENTITY" --identifier dev.pawel.secrets "$BIN_DIR/.secrets.new"
mv -f "$BIN_DIR/.secrets.new" "$BIN_DIR/secrets"

# The daemon log records key NAMES, namespaces and requesting pids/paths (never
# values) — still not for other accounts' eyes. launchd appends to an existing
# file without touching its mode, so create them 0600 before it does.
chmod 700 "$LOG_DIR"
touch "$LOG_DIR/secretsd.out.log" "$LOG_DIR/secretsd.err.log"
chmod 600 "$LOG_DIR"/secretsd.*.log

sed -e "s|__BIN_PATH__|$BIN_DIR/secrets|g" -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$REPO_DIR/LaunchAgents/$LABEL.plist" > "$PLIST_PATH"

launchctl bootstrap "gui/$(id -u)" "$PLIST_PATH"

echo
echo "Installed."
echo "  binary:      $BIN_DIR/secrets"
echo "  launchagent: $PLIST_PATH"
echo "  logs:        $LOG_DIR"
echo
echo "Make sure $BIN_DIR is on your PATH (it already is if you use ~/.local/bin for other tools)."
echo "Run 'secrets unlock' once to authorize this Claude/terminal session with Touch ID."
