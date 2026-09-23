import Foundation
import Security

enum KeychainError: Error, CustomStringConvertible {
    case unhandled(OSStatus)
    case notFound

    var description: String {
        switch self {
        case .unhandled(let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
            return "keychain error \(status): \(message)"
        case .notFound:
            return "not found"
        }
    }
}

/// Stores each secret as its own generic-password item, one Keychain
/// *service* per namespace (`dev.pawel.secrets.<namespace>`) so different
/// apps/projects (e.g. `movies`, `bitcashier`) land in genuinely separate
/// buckets, not just separate labels within one bucket.
///
/// No per-item `SecAccess` ACL is attached. An earlier version tried
/// restricting each item to "only this compiled binary" via the legacy
/// `SecAccess`/`SecTrustedApplication` API, but that ACL is keyed to the
/// binary's exact ad-hoc code signature — which has no stable identity
/// across rebuilds — so every rebuild orphaned every existing item's trust
/// and macOS re-prompted for a password, once per item, on next access.
/// With 80+ items that's unusable, and this tool gets rebuilt often. The
/// daemon's own Touch ID + session-pinning gate (see Daemon.swift) is the
/// actual security boundary; this ACL was a secondary layer against another
/// process on the same macOS account reading Keychain directly, and it
/// isn't workable to maintain against a tool under active iteration.
struct KeychainStore {
    static func service(for namespace: String) -> String {
        "dev.pawel.secrets.\(namespace)"
    }

    static func set(namespace: String, key: String, value: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: namespace),
            kSecAttrAccount as String: key
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError.unhandled(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw KeychainError.unhandled(updateStatus)
        }
    }

    static func get(namespace: String, key: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: namespace),
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw status == errSecItemNotFound ? KeychainError.notFound : KeychainError.unhandled(status)
        }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw KeychainError.notFound
        }
        return value
    }

    static func delete(namespace: String, key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: namespace),
            kSecAttrAccount as String: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandled(status)
        }
    }

    /// Stores a key's human description in the item's *comment attribute*,
    /// not inside its secret payload. Attributes are readable without the
    /// item's decrypt authorization, so `list` can show descriptions without
    /// ever touching a secret value — which matters because every item
    /// created by an older ad-hoc build of this tool still trusts only that
    /// build's exact code signature, and decrypting one raises a login
    /// keychain password prompt per item. Reading all of them to render
    /// `list` was a wall of 100+ prompts that "Always Allow" only ever
    /// cleared one at a time.
    static func setComment(namespace: String, key: String, comment: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: namespace),
            kSecAttrAccount as String: key
        ]
        let status = SecItemUpdate(query as CFDictionary, [kSecAttrComment as String: comment] as CFDictionary)
        guard status == errSecSuccess else {
            throw status == errSecItemNotFound ? KeychainError.notFound : KeychainError.unhandled(status)
        }
    }

    /// Key names with their comment attribute, read from attributes alone —
    /// never decrypts, so it never prompts, whichever build created an item.
    static func listWithComments(namespace: String) throws -> [(key: String, comment: String?)] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service(for: namespace),
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            throw KeychainError.unhandled(status)
        }
        return items
            .compactMap { item -> (key: String, comment: String?)? in
                guard let key = item[kSecAttrAccount as String] as? String else { return nil }
                let comment = (item[kSecAttrComment as String] as? String).flatMap { $0.isEmpty ? nil : $0 }
                return (key, comment)
            }
            .sorted { $0.key < $1.key }
    }
}
