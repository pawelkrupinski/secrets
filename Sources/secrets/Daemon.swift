import Foundation
import LocalAuthentication

func log(_ message: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    FileHandle.standardError.write("[\(timestamp)] \(message)\n".data(using: .utf8)!)
}

/// Holds the one piece of runtime state that matters: which single process
/// (a specific Claude Code session, or a specific bare shell) is currently
/// authorized, if any. Touch ID unlocks that one anchor; every other caller —
/// including a *different* Claude Code window/tab — stays locked until it
/// completes its own Touch ID prompt.
final class Daemon {
    private var trustedAnchor: SessionAnchor?
    private let queue = DispatchQueue(label: "dev.pawel.secrets.daemon")

    func handle(_ request: Request, peerPID: pid_t) -> Response {
        let anchor = ProcessAncestry.sessionAnchor(forPeerPID: peerPID)

        switch request.op {
        case "unlock":
            return unlock(anchor: anchor)
        case "lock":
            queue.sync { trustedAnchor = nil }
            log("locked")
            return Response(ok: true, value: nil, keys: nil, locked: true, error: nil)
        case "status":
            let isUnlocked = queue.sync { isCallerAuthorized(anchor) }
            return Response(ok: true, value: nil, keys: nil, locked: !isUnlocked, error: nil)
        case "get":
            return requireUnlocked(anchor) {
                do {
                    let value = try KeychainStore.get(key: request.key ?? "")
                    return Response(ok: true, value: value, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }
        case "set":
            return requireUnlocked(anchor) {
                do {
                    try KeychainStore.set(key: request.key ?? "", value: request.value ?? "")
                    log("set \(request.key ?? "?")")
                    return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }
        case "delete":
            return requireUnlocked(anchor) {
                do {
                    try KeychainStore.delete(key: request.key ?? "")
                    log("deleted \(request.key ?? "?")")
                    return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }
        case "list":
            return requireUnlocked(anchor) {
                do {
                    let keys = try KeychainStore.list()
                    return Response(ok: true, value: nil, keys: keys, locked: false, error: nil)
                } catch {
                    return Response(ok: false, value: nil, keys: nil, locked: false, error: "\(error)")
                }
            }
        default:
            return Response(ok: false, value: nil, keys: nil, locked: nil, error: "unknown op \(request.op)")
        }
    }

    /// Must be called while holding `queue`, or from a context where a stale
    /// read is acceptable (status/requireUnlocked both re-check on `queue`).
    private func isCallerAuthorized(_ anchor: SessionAnchor?) -> Bool {
        guard let trustedAnchor, let anchor else { return false }
        guard trustedAnchor == anchor else { return false }
        guard ProcessAncestry.isAnchorStillValid(trustedAnchor) else {
            self.trustedAnchor = nil
            return false
        }
        return true
    }

    private func requireUnlocked(_ anchor: SessionAnchor?, _ body: () -> Response) -> Response {
        let authorized = queue.sync { isCallerAuthorized(anchor) }
        guard authorized else {
            return Response(ok: false, value: nil, keys: nil, locked: true, error: "locked — run `secrets unlock`")
        }
        return body()
    }

    private func unlock(anchor: SessionAnchor?) -> Response {
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

        let reason = "Unlock the secrets store for \((anchor.path as NSString).lastPathComponent) (pid \(anchor.pid))"
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
            queue.sync { trustedAnchor = anchor }
            log("unlocked for pid \(anchor.pid) (\(anchor.path))")
            return Response(ok: true, value: nil, keys: nil, locked: false, error: nil)
        } else {
            log("unlock failed: \(failureReason ?? "unknown")")
            return Response(ok: false, value: nil, keys: nil, locked: true, error: failureReason ?? "authentication failed")
        }
    }
}
