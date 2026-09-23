#!/usr/bin/env bash
# One-time migration of every secret from the per-build v1 keychain items
# (service dev.pawel.secrets.<ns>) to v2 items created by the Apple-Development-
# signed build (dev.pawel.secrets.v2.<ns>), then installs that build.
#
# WHY IT CAN RUN WITHOUT A PASSWORD PROMPT PER ITEM: v1 items trust the exact
# cdhash of the ad-hoc build that created them, and builds of this repo made
# IN PLACE are byte-identical -- so rebuilding those commits here reproduces
# binaries the items already trust. Each item is read by the build it trusts
# and written by the new signed daemon, then read back and compared by hash.
# Values are never printed. The v1 items are left in place (see the end).
#
# Touch ID prompts: one per (daemon, namespace) unlock -- expect about six.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo "working tree not clean" >&2; exit 1; }
BRANCH=$(git rev-parse --abbrev-ref HEAD)
W=$(mktemp -d)
SUP="$HOME/Library/Application Support/secrets"
NEW_SOCK="$SUP/m.sock"
IDENTITY="${SECRETS_CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)}"

# Readers: commit -> cdhash prefix its v1 items trust.
READERS="53df79e:a9a93fa19a 1e5f1b8:1663eaf786 2a4776e:6fca6310fa cb01785:7df21665ec"
for r in $READERS; do
  c=${r%%:*}; h=${r##*:}
  git checkout -q "$c"; swift build -c release >/dev/null
  got=$(codesign -dvvv .build/release/secrets 2>&1 | sed -n 's/^CDHash=//p')
  [ "${got:0:10}" = "$h" ] || { git checkout -q "$BRANCH"; echo "build of $c is $got, not $h -- not reproducible here" >&2; exit 1; }
  cp .build/release/secrets "$W/old-$h"
done
git checkout -q "$BRANCH"; swift build -c release >/dev/null
cp .build/release/secrets "$W/new"
codesign --force --sign "$IDENTITY" --identifier dev.pawel.secrets "$W/new"

launchctl bootout "gui/$(id -u)/dev.pawel.secretsd" >/dev/null 2>&1 || true
SECRETS_SOCKET_PATH="$NEW_SOCK" "$W/new" daemon >"$W/new.log" 2>&1 &
NEWPID=$!
new() { SECRETS_SOCKET_PATH="$NEW_SOCK" "$W/new" "$@"; }
sha() { shasum -a 256 | cut -c1-64; }
sleep 1

NAMESPACES=$(security dump-keychain "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null \
  | sed -n 's/.*"svce"<blob>="dev\.pawel\.secrets\.\([A-Za-z0-9_-]*\)".*/\1/p' | grep -v '^v2$' | sort -u)
DUMP=$(security dump-keychain -a "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null)
for ns in $NAMESPACES; do new unlock "$ns" >/dev/null; done

done_keys="$W/done"; : > "$done_keys"; ok=0; fail=0
for r in $READERS; do
  h=${r##*:}
  old="$W/old-$h"
  for ns in $NAMESPACES; do
    keys=$(printf '%s' "$DUMP" | python3 -c '
import re,sys
ns,h=sys.argv[1],sys.argv[2]
for b in sys.stdin.read().split("keychain: "):
    if f"\"svce\"<blob>=\"dev.pawel.secrets.{ns}\"" not in b: continue
    if not any(r.startswith(h) for r in re.findall(r"requirement: cdhash H\"([0-9a-f]+)\"", b)): continue
    m=re.search(r"\"acct\"<blob>=\"([^\"]*)\"", b)
    if m: print(m.group(1))' "$ns" "$h" | sort -u)
    todo=$(printf '%s\n' "$keys" | while IFS= read -r k; do [ -n "$k" ] && ! grep -qxF "$ns/$k" "$done_keys" && echo "$k"; done || true)
    [ -z "$todo" ] && continue
    "$old" daemon >"$W/old.log" 2>&1 & OLDPID=$!; sleep 1
    "$old" unlock "$ns" >/dev/null
    while IFS= read -r key; do
      info=$("$old" list "$ns" "$key" 2>&1) || { echo "FAIL $ns/$key: $info"; fail=$((fail+1)); continue; }
      desc=$(printf '%s\n' "$info" | sed -n 's/^description: //p' | head -1)
      good=1
      while IFS= read -r label; do
        case "$label" in description:*|previous:*|"") continue ;; esac
        tags=(); [ "$label" != "(untagged)" ] && IFS=',' read -r -a tags <<< "$label"
        v=$("$old" get "$ns" "$key" ${tags[@]+"${tags[@]}"}; rc=$?; echo x; exit $rc) || { echo "FAIL $ns/$key [$label]: read"; good=0; continue; }
        v=${v%x}
        printf '%s' "$v" | new set "$ns" "$key" ${tags[@]+"${tags[@]}"} >/dev/null || { echo "FAIL $ns/$key [$label]: write"; good=0; continue; }
        [ "$(printf '%s' "$v" | sha)" = "$(new get "$ns" "$key" ${tags[@]+"${tags[@]}"} | sha)" ] || { echo "FAIL $ns/$key [$label]: verify"; good=0; }
        v=
      done <<< "$info"
      [ -n "$desc" ] && { printf '%s' "$desc" | new describe "$ns" "$key" >/dev/null || { echo "FAIL $ns/$key: describe"; good=0; }; }
      if [ $good = 1 ]; then ok=$((ok+1)); echo "$ns/$key" >> "$done_keys"; else fail=$((fail+1)); fi
    done <<< "$todo"
    kill $OLDPID; wait $OLDPID 2>/dev/null || true
  done
done
kill $NEWPID; wait $NEWPID 2>/dev/null || true
rm -f "$NEW_SOCK"

total=$(printf '%s' "$DUMP" | grep -c '"svce"<blob>="dev.pawel.secrets.[A-Za-z0-9_-]*"' || true)
echo "migrated $ok keys, $fail failed, of $total v1 items"
if [ "$fail" -gt 0 ] || [ "$ok" -lt "$total" ]; then
  echo "NOT installing -- the v1 LaunchAgent is restored unchanged." >&2
  launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.pawel.secretsd.plist"
  rm -rf "$W"; exit 1
fi
rm -rf "$W"
scripts/install.sh
echo
echo "Done. The v1 items (service dev.pawel.secrets.<ns>, no v2) are still in the login keychain;"
echo "once you are happy, delete them in Keychain Access (search dev.pawel.secrets.)."
