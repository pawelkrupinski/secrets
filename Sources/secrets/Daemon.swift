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

/// Holds the runtime state that matters: for each authorized process
/// ("session anchor" — a specific Claude Code session, or a specific bare
/// shell), which namespaces it has separately unlocked with Touch ID.
/// Unlocking `movies` never authorizes `bitcashier`, even for the exact same
/// session — each namespace is its own Touch ID grant, since an agent is
/// never meant to be working across both at once.
final class Daemon {
    private var authorizedNamespaces: [SessionAnchor: Set<String>] = [:]
    private let queue = DispatchQueue(label: "dev.pawel.secrets.daemon")

    func handle(_ request: Request, peerPID: pid_t) -> Response {
        let anchor = ProcessAncestry.sessionAnchor(forPeerPID: peerPID)

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
                        let variants = try TaggedSecrets.listVariants(namespace: namespace, key: key)
                        return Response(ok: true, value: nil, keys: variants, locked: false, error: nil)
                    }
                    let keys = try KeychainStore.list(namespace: namespace)
                    return Response(ok: true, value: nil, keys: keys, locked: false, error: nil)
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

        let reason = "Unlock the '\(namespace)' secrets for \((anchor.path as NSString).lastPathComponent) (pid \(anchor.pid))"
        let semaphore = DispatchSemaphore(value: 0)
        var success = false
        var failureReason: String?
        context.evaluatePolicy(policy, localizedReason: reason) { result, error in
            success = result
            failureReason = error?.localizedDescription
            semaphore.signal()
        }
        semaphore.wait()

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
