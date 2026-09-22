import Foundation
import LocalAuthentication

func log(_ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write("[\(timestamp)] \(message)\n".data(using: .utf8)!)
}

/// Namespace names double as Keychain service-name suffixes, so keep them to
/// a conservative charset — no "/", spaces, or anything that would make two
/// different-looking namespaces collide.
func isValidNamespace(_ namespace: String) -> Bool {
    guard !namespace.isEmpty, namespace.count <= 64 else { return false }
    return namespace.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
}

/// Key names, tag keys and tag values are stored as Keychain attributes and
/// printed straight back by `list`. A control character in one — ESC above
/// all — would be interpreted by the terminal that prints it (CSI/OSC
/// sequences can rewrite what's on screen, or in some terminals write the
/// clipboard), so they're refused at the boundary.
func hasControlCharacters(_ text: String) -> Bool {
    text.unicodeScalars.contains { $0.value < 0x20 || (0x7F...0x9F).contains($0.value) }
}

/// Descriptions are free text and might legitimately hold a tab; everything
/// else below 0x20, plus DEL and the C1 range, is dropped before a
/// description is echoed to a terminal. A newline in particular would let one
/// entry's description masquerade as another `list` line.
func sanitizedForTerminal(_ text: String) -> String {
    String(String.UnicodeScalarView(text.unicodeScalars.filter {
        $0 == "\t" || !($0.value < 0x20 || (0x7F...0x9F).contains($0.value))
    }))
}

private func invalidName(in request: Request) -> String? {
    if let key = request.key, key.isEmpty || key.count > 256 || hasControlCharacters(key) {
        return "invalid key name (empty, over 256 characters, or contains control characters)"
    }
    for (tagKey, tagValue) in request.tags ?? [:]
    where tagKey.isEmpty || tagValue.isEmpty || hasControlCharacters(tagKey) || hasControlCharacters(tagValue) {
        return "invalid tag (empty, or contains control characters)"
    }
    return nil
}

/// Holds the runtime state that matters: for each authorized process
/// ("session anchor" — a specific Claude Code session, or a specific bare
/// shell), which namespaces it has separately unlocked with Touch ID.
/// Unlocking `movies` never authorizes `bitcashier`, even for the exact same
/// session — each namespace is its own Touch ID grant, since an agent is
/// never meant to be working across both at once.
final class Daemon {
    private var authorizedNamespaces: [SessionAnchor: Set<String>] = [:]
    private let queue = DispatchQueue(label: "dev.pawel.secrets.daemon")
    /// One Touch ID prompt at a time. Without this, any local process could
    /// fire off dozens of `unlock` requests and stack up that many system
    /// dialogs — an easy way to tire a user into approving the wrong one, and
    /// each one pins a handler thread for as long as the prompt stays open.
    private let unlockGate = DispatchSemaphore(value: 1)

    func handle(_ request: Request, peerPID: pid_t) -> Response {
        let anchor = ProcessAncestry.sessionAnchor(forPeerPID: peerPID)

        if let problem = invalidName(in: request) {
            return Response(ok: false, value: nil, keys: nil, locked: nil, error: problem)
        }

        switch request.op {
        case "unlock":
            guard let namespace = request.namespace, isValidNamespace(namespace) else {
                return Response(ok: false, value: nil, keys: nil, locked: true,
                                 error: "unlock requires a namespace, e.g. `secrets unlock movies`")
            }
            return unlock(anchor: anchor, namespace: namespace)

        case "lock":
            queue.sync {
                guard let anchor else { return }
                if let namespace = request.namespace {
                    authorizedNamespaces[anchor]?.remove(namespace)
                } else {
                    authorizedNamespaces[anchor] = nil
                }
            }
            log("locked \(request.namespace ?? "(all namespaces)")")
            return Response(ok: true, value: nil, keys: nil, locked: true, error: nil)

        case "lock-all":
            // Deliberately available to ANY local caller, not just the
            // sessions being locked: locking only ever removes access, so the
            // worst a stranger can do with it is force a fresh Touch ID. That
            // makes it a safe panic switch when something looks wrong and the
            // user isn't sitting in the session that holds the unlock.
            queue.sync { authorizedNamespaces.removeAll() }
            log("lock-all: cleared every session's unlocks (requested by pid \(peerPID))")
            return Response(ok: true, value: nil, keys: nil, locked: true, error: nil)

        case "status":
            let unlocked = queue.sync { liveNamespaces(for: anchor) }
            if let namespace = request.namespace {
                return Response(ok: true, value: nil, keys: nil, locked: !unlocked.contains(namespace), error: nil)
            }
            return Response(ok: true, value: nil, keys: unlocked.sorted(), locked: unlocked.isEmpty, error: nil)

        case "get":
            return requireUnlocked(anchor, namespace: request.namespace) { namespace in
                do {
                    let value = try TaggedSecrets.get(namespace: namespace, key: request.key ?? "", tags: request.tags ?? [:])
                    return Response(ok: true, value: value, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }

        case "set":
            return requireUnlocked(anchor, namespace: request.namespace) { namespace in
                do {
                    let tags = request.tags ?? [:]
                    try TaggedSecrets.set(namespace: namespace, key: request.key ?? "", tags: tags, value: request.value ?? "")
                    log("set \(namespace)/\(request.key ?? "?") \(TaggedSecrets.canonicalLabel(tags))")
                    return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }

        case "delete":
            return requireUnlocked(anchor, namespace: request.namespace) { namespace in
                do {
                    let tags = request.tags ?? [:]
                    try TaggedSecrets.delete(namespace: namespace, key: request.key ?? "", tags: tags)
                    log("deleted \(namespace)/\(request.key ?? "?") \(TaggedSecrets.canonicalLabel(tags))")
                    return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }

        case "list":
            return requireUnlocked(anchor, namespace: request.namespace) { namespace in
                do {
                    if let key = request.key {
                        var lines: [String] = []
                        if let description = TaggedSecrets.getDescription(namespace: namespace, key: key) {
                            lines.append("description: \(sanitizedForTerminal(description))")
                        }
                        lines += try TaggedSecrets.listVariants(namespace: namespace, key: key)
                        return Response(ok: true, value: nil, keys: lines, locked: false, error: nil)
                    }
                    let keys = try KeychainStore.list(namespace: namespace)
                    let lines = keys.map { key -> String in
                        if let description = TaggedSecrets.getDescription(namespace: namespace, key: key) {
                            return "\(key) — \(sanitizedForTerminal(description))"
                        }
                        return key
                    }
                    return Response(ok: true, value: nil, keys: lines, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }

        case "describe":
            return requireUnlocked(anchor, namespace: request.namespace) { namespace in
                do {
                    try TaggedSecrets.setDescription(namespace: namespace, key: request.key ?? "", description: request.value ?? "")
                    log("described \(namespace)/\(request.key ?? "?")")
                    return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }

        default:
            return Response(ok: false, value: nil, keys: nil, locked: nil, error: "unknown op \(request.op)")
        }
    }

    /// Must be called on `queue`. Drops the anchor's whole entry if its pinned
    /// process has died (or been reused by something else), rather than
    /// silently leaking permission to a lucky new process at the same pid.
    private func liveNamespaces(for anchor: SessionAnchor?) -> Set<String> {
        guard let anchor, let namespaces = authorizedNamespaces[anchor] else { return [] }
        guard ProcessAncestry.isAnchorStillValid(anchor) else {
            authorizedNamespaces[anchor] = nil
            return []
        }
        return namespaces
    }

    private func requireUnlocked(_ anchor: SessionAnchor?, namespace: String?, _ body: (String) -> Response) -> Response {
        guard let namespace, isValidNamespace(namespace) else {
            return Response(ok: false, value: nil, keys: nil, locked: true, error: "missing or invalid namespace")
        }
        let isUnlocked = queue.sync { liveNamespaces(for: anchor).contains(namespace) }
        guard isUnlocked else {
            return Response(ok: false, value: nil, keys: nil, locked: true,
                             error: "locked — run `secrets unlock \(namespace)`")
        }
        return body(namespace)
    }

    private func unlock(anchor: SessionAnchor?, namespace: String) -> Response {
        guard let anchor else {
            return Response(ok: false, value: nil, keys: nil, locked: true, error: "could not identify caller process")
        }

        guard unlockGate.wait(timeout: .now()) == .success else {
            return Response(ok: false, value: nil, keys: nil, locked: true,
                             error: "another unlock prompt is already open — answer or dismiss it first")
        }
        defer { unlockGate.signal() }

        let context = LAContext()
        var policy: LAPolicy = .deviceOwnerAuthenticationWithBiometrics
        var evalError: NSError?
        if !context.canEvaluatePolicy(policy, error: &evalError) {
            policy = .deviceOwnerAuthentication
            guard context.canEvaluatePolicy(policy, error: &evalError) else {
                return Response(ok: false, value: nil, keys: nil, locked: true,
                                 error: "authentication unavailable: \(evalError?.localizedDescription ?? "unknown")")
            }
        }

        // The prompt is the user's only chance to notice a request they didn't
        // make: any local process can ask for an unlock and hope the user
        // approves it reflexively. Naming the exact requesting executable and
        // pid lets an unexpected one stand out; a bare basename like "zsh"
        // wouldn't.
        let displayPath = anchor.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")
        let reason = "Unlock '\(namespace)' for \(displayPath) (pid \(anchor.pid))"
        let semaphore = DispatchSemaphore(value: 0)
        var success = false
        var failureReason: String?
        context.evaluatePolicy(policy, localizedReason: reason) { result, error in
            success = result
            failureReason = error?.localizedDescription
            semaphore.signal()
        }
        // LocalAuthentication has its own timeout, but nothing here should
        // rest on it: a prompt that somehow never resolves would otherwise
        // hold the unlock gate — and every future unlock — until a restart.
        if semaphore.wait(timeout: .now() + 300) == .timedOut {
            context.invalidate()
            log("unlock of '\(namespace)' abandoned: prompt unanswered for 5 minutes")
            return Response(ok: false, value: nil, keys: nil, locked: true, error: "Touch ID prompt timed out")
        }

        if success {
            queue.sync { _ = authorizedNamespaces[anchor, default: []].insert(namespace) }
            log("unlocked namespace '\(namespace)' for pid \(anchor.pid) (\(anchor.path))")
            return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
        } else {
            log("unlock of '\(namespace)' failed: \(failureReason ?? "unknown")")
            return Response(ok: false, value: nil, keys: nil, locked: true, error: failureReason ?? "authentication failed")
        }
    }
}
