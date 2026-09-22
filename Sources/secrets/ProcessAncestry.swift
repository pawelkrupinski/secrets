import Darwin
import Foundation

/// Identifies the process that should be trusted for a given socket connection,
/// so the daemon can pin an unlock to one specific Claude Code session (or one
/// bare terminal shell) instead of trusting every process the Mac user owns.
///
/// `startTime` is what makes the pin hold up against pid reuse: pids are
/// recycled, and a later process — including another `claude` at the very same
/// executable path, e.g. the next session the user opens — could otherwise land
/// on a pid that a dead session had unlocked. A (pid, path, start time) triple
/// names one specific process instance, not just a pid.
struct SessionAnchor: Hashable {
    let pid: pid_t
    let path: String
    let startTime: UInt64
}

enum ProcessAncestry {
    /// The macOS peer-credentials sockopt for AF_UNIX sockets: gives the pid of
    /// whatever process is on the other end of an accepted connection.
    static func peerPID(of socketFD: Int32) -> pid_t? {
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        let result = getsockopt(socketFD, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
        return result == 0 ? pid : nil
    }

    // PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN) — the macro itself is marked
    // unavailable to Swift on this SDK, so the value is inlined here.
    private static let maxPathInfoSize = 4 * 1024

    static func executablePath(of pid: pid_t) -> String? {
        var buffer = [Int8](repeating: 0, count: maxPathInfoSize)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    private static func bsdInfo(of pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        return result == size ? info : nil
    }

    static func parentPID(of pid: pid_t) -> pid_t? {
        bsdInfo(of: pid).map { pid_t(bitPattern: $0.pbi_ppid) }
    }

    /// Whole seconds since the epoch at which the process started, as the
    /// kernel records it — stable for the life of the process, different for
    /// any later process that reuses its pid.
    static func startTime(of pid: pid_t) -> UInt64? {
        bsdInfo(of: pid).map { $0.pbi_start_tvsec }
    }

    private static func anchor(for pid: pid_t) -> SessionAnchor? {
        guard let path = executablePath(of: pid), let start = startTime(of: pid) else { return nil }
        return SessionAnchor(pid: pid, path: path, startTime: start)
    }

    /// Claude Code's actual running binary is a versioned file under
    /// `.../claude/versions/<version>` (its kernel "comm" name is just the
    /// version string, e.g. "2.1.278") — the "claude" you invoke is a
    /// launcher shim, not the process itself. So match either a literal
    /// `claude` executable name, or that versions-directory shape.
    private static func looksLikeClaudeCode(_ path: String) -> Bool {
        if (path as NSString).lastPathComponent == "claude" { return true }
        let components = path.split(separator: "/")
        guard components.count >= 3 else { return false }
        return components[components.count - 2] == "versions"
            && components[components.count - 3] == "claude"
    }

    /// Walks up the caller's parent chain looking for a Claude Code process
    /// (any session, terminal-launched or IDE-embedded). Falls back to the
    /// immediate parent — typically the login shell — when no such ancestor
    /// exists within range, so running the CLI from a bare terminal still
    /// pins to *that* shell rather than being rejected outright.
    static func sessionAnchor(forPeerPID peerPID: pid_t, maxDepth: Int = 24) -> SessionAnchor? {
        var pid = peerPID
        var fallback: SessionAnchor?
        for _ in 0..<maxDepth {
            guard let parent = parentPID(of: pid), parent > 1 else { break }
            guard let candidate = anchor(for: parent) else { break }
            if fallback == nil {
                fallback = candidate
            }
            if looksLikeClaudeCode(candidate.path) {
                return candidate
            }
            pid = parent
        }
        return fallback
    }

    /// Re-checks that the pinned anchor is still the same live process
    /// instance: same executable AND same start time, so a later process that
    /// reuses the pid — even one running the same binary — doesn't inherit it.
    static func isAnchorStillValid(_ anchor: SessionAnchor) -> Bool {
        executablePath(of: anchor.pid) == anchor.path && startTime(of: anchor.pid) == anchor.startTime
    }
}
