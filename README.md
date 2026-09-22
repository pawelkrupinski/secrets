# secrets

A tiny macOS daemon + CLI that stores API keys and passwords in the
Keychain, and gates access behind Touch ID — scoped to *one specific
Claude Code session* (or one specific terminal shell) at a time, so an
unlock in one window can't be used by a different Claude session or
process.

## Why not just use the Keychain / 1Password CLI directly?

- Raw Keychain items protected with a biometry ACL (`kSecAccessControlBiometryCurrentSet`)
  prompt for Touch ID on *every single read*, which is unworkable when an
  agent needs to fetch several secrets per task.
- 1Password's CLI biometric unlock authorizes your whole user session/app
  state, not a specific caller — any process that can shell out to `op`
  during the unlocked window can read secrets.

This tool trades a bit of DIY complexity for a session-pinned unlock: one
Touch ID prompt authorizes exactly the process that asked for it (and its
descendants), for as long as that process stays alive.

## Architecture

```
 Claude Code (pid 90522, "claude")
   └─ Bash tool spawns: zsh -c "secrets get movies TMDB_API_KEY"
        └─ secrets (CLI, connects to Unix socket)
             │  JSON line over
             │  ~/Library/Application Support/secrets/secrets.sock
             ▼
        secretsd (daemon, LaunchAgent, always running)
             │  1. reads the peer pid off the socket (LOCAL_PEERPID)
             │  2. walks the parent-pid chain looking for a Claude Code
             │     process (or falls back to the immediate parent shell)
             │  3. checks whether that "session anchor" has separately
             │     unlocked the "movies" namespace
             ▼
        Keychain (service "dev.pawel.secrets.movies", one item per key)
```

### The security model

- **Storage**: each secret is a `kSecClassGenericPassword` Keychain item,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never synced, requires
  the Mac to be unlocked at all), one Keychain *service* per namespace. No
  per-item `SecAccess` ACL restricts *which app* can read it — a version of
  this tool tried that (trusting only the compiled `secrets` binary,
  because plain `SecItemAdd` leaves items readable by any same-user process
  via `security find-generic-password -w`), but that ACL is keyed to the
  binary's exact ad-hoc code signature, which has no stable identity across
  rebuilds. Every rebuild orphaned every existing item's trust and macOS
  re-prompted for the login password once per item on next access — with
  80+ items, unusable, and this tool gets rebuilt often. Dropped. The
  daemon's own gate below is the actual security boundary; a raw
  `security find-generic-password -w` by another same-user process can
  still read a value directly, same as any other same-user Keychain access
  — that's the accepted same-user trust boundary here (see Caveats below),
  not a gap this tool tries to close.
- **The daemon's own gate**: the daemon tracks, per session anchor (see
  below), which namespaces it separately unlocked with Touch ID. Every
  `get`/`set`/`delete`/`list` request re-derives the caller's anchor and
  only serves the request if that anchor has that *specific namespace*
  unlocked — re-verified against a live `proc_pidpath` lookup each time,
  so a later, unrelated process reusing the same pid can't inherit trust.
- **Session pinning, not machine-wide unlock**: unlocking from inside a
  Claude Code conversation pins trust to *that* Claude Code process. A
  different Claude Code window/tab, a different IDE-embedded Claude
  session, or any other app on your Mac is a different anchor and gets
  `locked` — it has to complete its own Touch ID prompt. Running `secrets
  unlock` from a bare terminal (no Claude ancestor) pins to that shell
  instead, so manual use works the same way.
- **Namespace pinning**: unlocking is per (session anchor, namespace) —
  unlocking `movies` for a session never authorizes `bitcashier` for that
  same session. Each app/project gets its own Touch ID grant.
- **Self-locking**: there's no explicit TTL. Trust lasts exactly as long
  as the pinned process stays alive — close that Claude Code conversation
  (or terminal) and the next `get` from anywhere fails closed, requiring
  a fresh Touch ID prompt. `secrets lock [namespace]` ends it early on demand.
- **Pid reuse can't inherit a session**: the anchor is (pid, executable
  path, process start time), and every request re-reads all three. A later
  process that lands on a dead session's pid — even another `claude` at the
  same path, like the next session you open — has a different start time and
  gets `locked`.
- **The unlock prompt names the requester**: any local process can *ask*
  for an unlock and hope you approve reflexively. The Touch ID dialog shows
  the exact requesting executable path and pid, so only approve one when
  you just ran `secrets unlock` yourself and it names what you expect. Only
  one prompt can be open at a time — further `unlock` requests are refused
  until it's answered — so a process can't stack up dialogs to wear you
  down. `secrets lock-all` clears every session's unlocks from anywhere
  (locking only removes access, so it's safe for any caller to have).
- **Typed input is hidden**: `secrets set` reading from a terminal turns
  off echo, so the value isn't on screen or in scrollback.
- **Daemon hardening against local misuse**: `SIGPIPE` is ignored (a client
  that disconnects before reading its reply used to kill the daemon and wipe
  every session's unlock — any local process could do that on purpose);
  requests are capped at 4 MiB and socket I/O times out, so a client can't
  exhaust memory or pin a handler thread; in-flight connections are capped
  at 32 (beyond that, closed on arrival) so a process holding thousands
  open can't exhaust the daemon's file descriptors; key names and tags are
  refused if they contain control characters, and descriptions are
  stripped of them on output, so nothing stored can drive the terminal
  that `list` prints to (escape-sequence injection); the socket is created
  under a `077` umask (never briefly world-connectable), in a `0700`
  directory, and the daemon log — key names and requester pids only, never
  values — is `0600`.
- **What this does *not* protect against**: anything already running
  inside the trusted process's own descendants during the unlocked window
  (e.g. another Bash tool call in the *same* Claude conversation, for the
  *same* namespace) is, by design, allowed — that's the whole point of
  "authorize this session for this namespace." Be aware of what that
  includes: every **MCP server** and hook Claude Code launches is a child
  of that same `claude` process, so third-party MCP servers you've
  configured can read whatever the session has unlocked. Unlock only the
  namespace the task needs, and `lock` when it's done. It also doesn't protect
  against another process that has already compromised the same macOS
  user account and can inject itself as a child of the trusted pid.

## Setup

Requires Xcode command line tools (`swift build`) and a Mac with Touch ID.

```sh
cd ~/projects/secrets
./scripts/install.sh
```

This builds a release binary, installs it to `~/.local/bin/secrets`,
writes `~/Library/LaunchAgents/dev.pawel.secretsd.plist`, and loads it
with `launchctl` so the daemon starts now and on every login. It starts
**locked** — nothing is served until the first `secrets unlock`.

Make sure `~/.local/bin` is on your `PATH`.

## Namespaces

Every command takes a namespace — one per app/project (e.g. `movies`,
`bitcashier`). Namespaces are a real security boundary, not just labels:

- Each namespace is its own Keychain service
  (`dev.pawel.secrets.<namespace>`) — separate storage buckets.
- Each namespace is its own Touch ID grant. Unlocking `movies` does
  **not** authorize `bitcashier`, even for the exact same session pin —
  you unlock each namespace you need, separately. This matches how an
  agent actually works: it's on one project at a time, so there's no
  reason a `movies` task should ever be able to read `bitcashier` secrets
  just because they happen to run in the same Claude Code conversation.

`secrets status` with no namespace lists everything currently unlocked
for this session; `secrets lock` with no namespace locks all of them.

## Tagged variants

Within a namespace, one KEY can hold several tagged variants of the same
secret — e.g. a `MONGODB_URI` that differs per `environment`/`app`. Storage
stays a single Keychain item per key either way: the first time a key gets
a tagged `set`, its value becomes a small JSON envelope
(`{"secretsVaultVariants": true, "variants": [...]}`) holding one
`{tags, value}` pair per variant instead of a plain string. Every key set
before this feature, or that's never used tags, stays a plain string
untouched — `get`/`set` handle both shapes transparently, so nothing needed
migrating.

Resolution rule for `get`: tags you *ask for* must match a stored variant
exactly, always — `get KEY environment=production` never returns anything
but a variant tagged exactly that, even if the key's only variant is
`environment=development`. (An earlier version waved a single variant
through regardless of requested tags; that quietly handed back the wrong
environment's credential, which is the one thing tags exist to prevent.)
Asking with *no* tags returns the untagged variant, or — when a key has
exactly one variant and nothing to disambiguate — that one. Anything else
fails loudly, listing what *is* available, rather than guessing.

```sh
secrets set movies MONGODB_URI environment=production app=web    <<< "mongodb://prod-web..."
secrets set movies MONGODB_URI environment=production app=worker <<< "mongodb://prod-worker..."
secrets get movies MONGODB_URI environment=production app=web    # exact match required now
secrets get movies MONGODB_URI                                   # error: ambiguous, lists both
secrets list movies MONGODB_URI                                  # variant labels, never values:
                                                                   #   app=web,environment=production
                                                                   #   app=worker,environment=production
secrets delete movies MONGODB_URI environment=production app=web # removes just that one variant
```

## Usage

```sh
secrets unlock movies                        # Touch ID prompt; authorizes this session for "movies" only
secrets status                                # lists which namespaces are unlocked for this session
secrets status movies                         # "locked" or "unlocked", for just that namespace
secrets set movies TMDB_API_KEY   <<< "abc123"   # value read from stdin
secrets get movies TMDB_API_KEY                  # prints the raw value
secrets list movies              # key names only, never values
secrets delete movies TMDB_API_KEY
secrets undo movies TMDB_API_KEY   # put back whatever the last `set` overwrote (one level)
secrets lock movies              # end authorization for just "movies"
secrets lock                     # end authorization for every namespace (this session)
secrets lock-all                 # panic switch: clear EVERY session's unlocks, from any terminal
```

`set` reads the value from stdin rather than argv, so it never shows up
in `ps` the way a literal `secrets set KEY value` would. Note that a
here-string (`<<< "value"`) typed at an interactive prompt *is* still
recorded in your shell history as part of the command line — for anything
sensitive, pipe from a file or use a heredoc in a script rather than
typing the value inline:

```sh
secrets set movies OMDB_API_KEY <<'EOF'
your-real-key-here
EOF
```

### How Claude Code uses this

Once you've run `secrets unlock` yourself in the same Claude Code
conversation (Touch ID requires an actual human touch — Claude can run
the command, but you still have to complete the prompt), every
subsequent Bash tool call Claude makes in *that same conversation* can
do:

```sh
secrets get movies TMDB_API_KEY
```

and get the value back directly, with no further prompting, because
those Bash calls are descendants of the same `claude` process that got
authorized.

## Uninstall

```sh
./scripts/uninstall.sh
```

Removes the LaunchAgent, the daemon, and the CLI binary. Leaves the
Keychain items in place — delete them yourself via Keychain Access.app
(search for service names starting with `dev.pawel.secrets.`) if you want
the secrets gone too.

## Caveats / things to know

- **Same-user trust boundary**: there's no per-item Keychain ACL (see why
  above), so this is an ssh-agent/gpg-agent-style model — the boundary is
  "your macOS user account," not "only this specific binary." Any process
  running as you can read a Keychain item's raw bytes directly via
  `security find-generic-password -w` if it knows the service/account
  names, same as it always could for any of your other Keychain items.
  What the daemon actually adds on top is the Touch ID gate and
  session/namespace pinning for the *intended* path (`secrets get`) — it
  doesn't and can't stop a determined same-user process from going around
  it via raw Keychain APIs. Accepted, not a bug: this matches the model the
  session-anchor design already assumes elsewhere (e.g. the Unix socket is
  only permission-gated by same-user, not per-process). Be clear-eyed
  about what the daemon-hardening items above therefore buy: a hostile
  process running as you can simply `kill` the daemon, `launchctl bootout`
  it, replace its binary, or read the Keychain directly — none of the
  socket-level protections stop that. They exist against careless or
  buggy local code, prompt-phishing, and other user accounts on the
  machine. Closing the same-user gap properly would mean the
  data-protection keychain (`kSecUseDataProtectionKeychain`), whose items
  are bound to a code-signing identity and invisible to `security(1)` —
  but that needs a real signing identity and entitlements, not an ad-hoc
  signed CLI, so it's not done here.
- **A mistaken overwrite is recoverable, once**: `set` on an existing
  value keeps the overwritten variant as `previous`, and `secrets undo`
  puts it back. Only the most recent overwrite is kept; `delete` has no
  undo, so `delete` deliberately refuses when nothing matches rather than
  reporting success for a no-op.
- **Rebuilding the binary**: no longer a concern for Keychain trust (no
  per-item ACL to invalidate). A rebuild does restart the daemon (via
  `install.sh`), which resets *all* sessions to locked — that's the normal
  "fresh unlock needed" case, not a permission prompt.
- **Touch ID vs password fallback**: the daemon asks for
  `.deviceOwnerAuthenticationWithBiometrics` first; if Touch ID hardware
  is unavailable (e.g. an external display in clamshell mode) it falls
  back to `.deviceOwnerAuthentication`, which accepts your login password
  too.
- **"All Claude sessions" instead of one**: if you'd rather any Claude
  Code process be trusted after one unlock (looser, more convenient,
  slightly less isolation between concurrent sessions), change
  `liveNamespaces` in `Daemon.swift` to compare `anchor.path` (or just "is
  there a Claude Code ancestor at all") instead of the exact pid. Not
  implemented by default — the pinned-session behavior above is the
  default.
