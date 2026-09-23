#!/usr/bin/env bash
# Deletes the pre-migration v1 keychain items (service dev.pawel.secrets.<ns>),
# after checking, variant by variant, that the v2 copy holds the same value.
#
# Only the build that CREATED a keychain item may delete it -- any other binary,
# Keychain Access and `security delete-generic-password` included, is refused or
# prompts per item. So, like migrate-to-v2.sh, this rebuilds in place the exact
# ad-hoc builds the items belong to and deletes each item through its own build.
# An item whose v2 copy is missing or different is left untouched and reported.
#
# Touch ID prompts: one per (daemon, namespace) unlock -- expect about five.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
BRANCH=$(git rev-parse --abbrev-ref HEAD)
W=$(mktemp -d)
SUP="$HOME/Library/Application Support/secrets"
NEW_SOCK="$SUP/m.sock"
KC="$HOME/Library/Keychains/login.keychain-db"

READERS="53df79e:a9a93fa19a 1e5f1b8:1663eaf786 2a4776e:6fca6310fa cb01785:7df21665ec"
for r in $READERS; do
  c=${r%%:*}; h=${r##*:}
  git checkout -q "$c"; swift build -c release >/dev/null
  got=$(codesign -dvvv .build/release/secrets 2>&1 | sed -n 's/^CDHash=//p')
  [ "${got:0:10}" = "$h" ] || { git checkout -q "$BRANCH"; echo "build of $c is $got, not $h" >&2; exit 1; }
  cp .build/release/secrets "$W/old-$h"
done
git checkout -q "$BRANCH"; swift build -c release >/dev/null

v1_items() {  # "<ns>\t<key>\t<trusted cdhash prefixes>" for every remaining v1 item, attributes only
  security dump-keychain -a "$KC" 2>/dev/null | python3 -c '
import re,sys
for b in sys.stdin.read().split("keychain: "):
    m=re.search(r"\"svce\"<blob>=\"dev\.pawel\.secrets\.([A-Za-z0-9_-]+)\"", b)
    a=re.search(r"\"acct\"<blob>=\"([^\"]*)\"", b)
    if not m or not a: continue
    hs=" ".join(sorted({h[:10] for h in re.findall(r"requirement: cdhash H\"([0-9a-f]+)\"", b)}))
    print(f"{m.group(1)}\t{a.group(1)}\t{hs}")'
}

launchctl bootout "gui/$(id -u)/dev.pawel.secretsd" >/dev/null 2>&1 || true
SECRETS_SOCKET_PATH="$NEW_SOCK" "$HOME/.local/bin/secrets" daemon >"$W/new.log" 2>&1 &
NEWPID=$!
new() { SECRETS_SOCKET_PATH="$NEW_SOCK" "$HOME/.local/bin/secrets" "$@"; }
sha() { shasum -a 256 | cut -c1-64; }
sleep 1
for ns in $(v1_items | cut -f1 | sort -u); do new unlock "$ns" >/dev/null; done

deleted=0; kept=0
for r in $READERS; do
  h=${r##*:}; old="$W/old-$h"
  for ns in $(v1_items | cut -f1 | sort -u); do
    keys=$(v1_items | awk -F'\t' -v ns="$ns" -v h="$h" '$1==ns && index($3,h) {print $2}')
    [ -z "$keys" ] && continue
    "$old" daemon >"$W/old.log" 2>&1 & OLDPID=$!; sleep 1
    "$old" unlock "$ns" >/dev/null
    while IFS= read -r key; do
      info=$("$old" list "$ns" "$key" 2>&1) || continue
      labels=$(printf '%s\n' "$info" | grep -vE '^(description:|previous:|$)' || true)
      same=1
      while IFS= read -r label; do
        tags=(); [ "$label" != "(untagged)" ] && IFS=',' read -r -a tags <<< "$label"
        a=$("$old" get "$ns" "$key" ${tags[@]+"${tags[@]}"} | sha) || { same=0; break; }
        b=$(new get "$ns" "$key" ${tags[@]+"${tags[@]}"} 2>/dev/null | sha) || { same=0; break; }
        [ "$a" = "$b" ] || { same=0; break; }
      done <<< "$labels"
      if [ $same = 0 ]; then echo "KEPT $ns/$key: v2 copy missing or different"; kept=$((kept+1)); continue; fi
      while IFS= read -r label; do
        tags=(); [ "$label" != "(untagged)" ] && IFS=',' read -r -a tags <<< "$label"
        "$old" delete "$ns" "$key" ${tags[@]+"${tags[@]}"} >/dev/null 2>&1 || true
      done <<< "$labels"
    done <<< "$keys"
    kill $OLDPID; wait $OLDPID 2>/dev/null || true
  done
done
kill $NEWPID; wait $NEWPID 2>/dev/null || true
rm -f "$NEW_SOCK"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.pawel.secretsd.plist"
rm -rf "$W"

left=$(v1_items | wc -l | tr -d ' ')
echo "v1 items remaining: $left (kept on purpose: $kept)"
[ "$left" = 0 ] || v1_items | cut -f1,2 | sed 's/^/  still present: /'
