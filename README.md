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
   └─ Bash tool spawns: zsh -c "secrets get TMDB_API_KEY"
        └─ secrets (CLI, connects to Unix socket)
             │  JSON line over
             │  ~/Library/Application Support/secrets/secrets.sock
             ▼
        secretsd (daemon, LaunchAgent, always running)
             │  1. reads the peer pid off the socket (LOCAL_PEERPID)
             │  2. walks the parent-pid chain looking for a `claude`
             │     ancestor (or falls back to the immediate parent shell)
             │  3. compares that "session anchor" against whichever one
             │     was pinned by the last successful `unlock`
             ▼
        Keychain (service "dev.pawel.secrets", one item per key)
```

### The security model

- **Storage**: each secret is a `kSecClassGenericPassword` Keychain item,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never synced, requires
  the Mac to be unlocked at all). Only the `secrets` binary that created
  an item can read it without an extra macOS keychain-access dialog — this
  is the default ACL Keychain gives the creating app, no extra code needed.
- **The daemon's own gate**: on top of that, the daemon tracks a single
  `trustedAnchor` — the pid + executable path of whichever process's
  ancestry successfully completed a Touch ID prompt. Every `get`/`set`/
  `delete`/`list` request re-derives the caller's anchor and only serves
  the request if it's the *same* anchor, re-verified against a live
  `proc_pidpath` lookup each time (so a later, unrelated process reusing
  that pid can't inherit trust).
- **Session pinning, not machine-wide unlock**: unlocking from inside a
  Claude Code conversation pins trust to *that* `claude` process. A
  different Claude Code window/tab, a different IDE-embedded Claude
  session, or any other app on your Mac is a different anchor and gets
  `locked` — it has to complete its own Touch ID prompt. Running `secrets
  unlock` from a bare terminal (no Claude ancestor) pins to that shell
  instead, so manual use works the same way.
- **Self-locking**: there's no explicit TTL. Trust lasts exactly as long
  as the pinned process stays alive — close that Claude Code conversation
  (or terminal) and the next `get` from anywhere fails closed, requiring
  a fresh Touch ID prompt. `secrets lock` ends it early on demand.
- **What this does *not* protect against**: anything already running
  inside the trusted process's own descendants during the unlocked window
  (e.g. another Bash tool call in the *same* Claude conversation) is, by
  design, allowed — that's the whole point of "authorize this session."
  It also doesn't protect against another process that has already
  compromised the same macOS user account and can inject itself as a
  child of the trusted `claude` pid.

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

## Usage

```sh
secrets unlock          # Touch ID prompt; authorizes this session
secrets status          # "locked" or "unlocked" (for the calling session)
secrets set TMDB_API_KEY   <<< "abc123"     # value read from stdin
secrets get TMDB_API_KEY                    # prints the raw value
secrets list             # key names only, never values
secrets delete TMDB_API_KEY
secrets lock             # end this session's authorization early
```

`set` reads the value from stdin rather than argv, so it never shows up
in `ps`/shell history the way a literal `secrets set KEY value` would.
Prefer a heredoc or pipe:

```sh
secrets set OMDB_API_KEY <<'EOF'
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
secrets get TMDB_API_KEY
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
(search for service `dev.pawel.secrets`) if you want the secrets gone too.

## Caveats / things to know

- **Rebuilding the binary**: macOS's Keychain ACL for "which app created
  this item" is tied to the binary's code signature. This binary is only
  ad-hoc self-signed (no Developer ID), so rebuilding it changes that
  signature. If you edit the code and reinstall, the *first* keychain
  access afterwards may trigger a one-time macOS "`secrets` wants to
  access your keychain" password prompt — click **Always Allow**. This
  is a one-time nuisance per rebuild, not a security issue.
- **Touch ID vs password fallback**: the daemon asks for
  `.deviceOwnerAuthenticationWithBiometrics` first; if Touch ID hardware
  is unavailable (e.g. an external display in clamshell mode) it falls
  back to `.deviceOwnerAuthentication`, which accepts your login password
  too.
- **"All Claude sessions" instead of one**: if you'd rather any Claude
  Code process be trusted after one unlock (looser, more convenient,
  slightly less isolation between concurrent sessions), change
  `isCallerAuthorized` in `Daemon.swift` to compare `anchor.path` (or just
  "is there a `claude` ancestor at all") instead of pinning the exact pid.
  Not implemented by default — the pinned-session behavior above is the
  default.
