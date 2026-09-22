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

/// Stores each secret as its own generic-password item under one service name.
///
/// `SecItemAdd` on its own does NOT restrict which app can read an item back —
/// that turned out to be a real gap here: `security find-generic-password -w`
/// could read a value straight out of Keychain, completely bypassing the
/// daemon's Touch ID gate. The fix is to attach an explicit access-control
/// list at creation time that trusts only the current process (the daemon),
/// via the legacy `SecAccess`/`SecTrustedApplication` API — still functional
/// for the classic file-based login keychain these items land in.
struct KeychainStore {
    static let service = "dev.pawel.secrets"

    private static func trustedToThisProcessOnly() throws -> SecAccess {
        var trustedApp: SecTrustedApplication?
        // path: nil means "the current process's own executable".
        let appStatus = SecTrustedApplicationCreateFromPath(nil, &trustedApp)
        guard appStatus == errSecSuccess, let app = trustedApp else {
            throw KeychainError.unhandled(appStatus)
        }
        var access: SecAccess?
        let accessStatus = SecAccessCreate("dev.pawel.secretsd" as CFString, [app] as CFArray, &access)
        guard accessStatus == errSecSuccess, let result = access else {
            throw KeychainError.unhandled(accessStatus)
        }
        return result
    }

    static func set(key: String, value: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            addQuery[kSecAttrAccess as String] = try trustedToThisProcessOnly()
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError.unhandled(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw KeychainError.unhandled(updateStatus)
        }
    }

    static func get(key: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
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

    static func delete(key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandled(status)
        }
    }

    static func list() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            throw KeychainError.unhandled(status)
        }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.sorted()
    }
}
