#!/usr/bin/env bash
set -euo pipefail

LABEL="dev.pawel.secretsd"

launchctl bootout "gui/$(id -u)/$LABEL" >/dev/null 2>&1 || true
rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
rm -f "$HOME/.local/bin/secrets"

echo "Uninstalled the daemon, LaunchAgent, and CLI binary."
echo "Keychain items under service 'dev.pawel.secrets' were left in place —"
echo "remove them manually via Keychain Access.app if you want them gone too."
