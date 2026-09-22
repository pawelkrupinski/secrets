import Foundation

/// One tagged value under a key — e.g. tags ["environment": "production",
/// "app": "web"] for a MONGODB_URI that differs per environment/app.
/// Empty tags is the untagged/default variant.
struct SecretVariant: Codable, Equatable {
    let tags: [String: String]
    let value: String
}

/// The on-disk shape for a key that has ever had a tagged SET or a
/// description. Marked with its own flag so a plain legacy value (any key
/// set before this feature existed, or any key that's never used tags or a
/// description) is never mistaken for one — a legacy value is just a raw
/// string, not JSON, so decoding this struct from it fails and callers fall
/// back to treating it as a single untagged value with no description.
/// That's what keeps every already-migrated secret working unchanged.
struct SecretEnvelope: Codable {
    var secretsVaultVariants: Bool
    var description: String?
    var variants: [SecretVariant]
}

enum TaggedSecretError: Error, CustomStringConvertible {
    case noVariantForTags(available: [[String: String]])
    case noValueYet

    var description: String {
        switch self {
        case .noVariantForTags(let available):
            return "no variant stored for those tags. Available: \(TaggedSecrets.describe(available))"
        case .noValueYet:
            return "no value stored for this key yet — `secrets set` it before describing it"
        }
    }
}

enum TaggedSecrets {
    static func describe(_ tagSets: [[String: String]]) -> String {
        if tagSets.isEmpty { return "(none)" }
        return tagSets.map(canonicalLabel).joined(separator: ", ")
    }

    static func canonicalLabel(_ tags: [String: String]) -> String {
        if tags.isEmpty { return "(untagged)" }
        return tags.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
    }

    private static func decodeEnvelope(_ raw: String) -> SecretEnvelope? {
        guard let data = raw.data(using: .utf8) else { return nil }
        guard let envelope = try? JSONDecoder().decode(SecretEnvelope.self, from: data) else { return nil }
        return envelope.secretsVaultVariants ? envelope : nil
    }

    private static func encodeEnvelope(_ envelope: SecretEnvelope) throws -> String {
        let data = try JSONEncoder().encode(envelope)
        return String(data: data, encoding: .utf8)!
    }

    static func get(namespace: String, key: String, tags: [String: String]) throws -> String {
        let raw = try KeychainStore.get(namespace: namespace, key: key)
        guard let envelope = decodeEnvelope(raw) else {
            // Legacy plain value — the only variant there is, always returned.
            return raw
        }
        // No ambiguity possible with exactly one variant, so it's returned
        // regardless of whatever tags were (or weren't) asked for. Only
        // 2+ variants force an exact tag match — that's the actual case
        // where guessing wrong would silently hand back the wrong
        // environment's/app's secret.
        if envelope.variants.count == 1 {
            return envelope.variants[0].value
        }
        if let match = envelope.variants.first(where: { $0.tags == tags }) {
            return match.value
        }
        throw TaggedSecretError.noVariantForTags(available: envelope.variants.map { $0.tags })
    }

    static func set(namespace: String, key: String, tags: [String: String], value: String) throws {
        let existingRaw = try? KeychainStore.get(namespace: namespace, key: key)

        if let existingRaw, let envelope = decodeEnvelope(existingRaw) {
            var variants = envelope.variants.filter { $0.tags != tags }
            variants.append(SecretVariant(tags: tags, value: value))
            let updated = SecretEnvelope(secretsVaultVariants: true, description: envelope.description, variants: variants)
            try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(updated))
            return
        }

        if tags.isEmpty {
            // No tags involved anywhere for this key — stay a plain value,
            // exactly like every secret set before this feature existed.
            try KeychainStore.set(namespace: namespace, key: key, value: value)
            return
        }

        // First tagged SET for this key. If a legacy plain value already
        // exists, preserve it as the untagged variant rather than clobbering it.
        var variants = [SecretVariant(tags: tags, value: value)]
        if let existingRaw {
            variants.append(SecretVariant(tags: [:], value: existingRaw))
        }
        let envelope = SecretEnvelope(secretsVaultVariants: true, description: nil, variants: variants)
        try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(envelope))
    }

    static func delete(namespace: String, key: String, tags: [String: String]) throws {
        guard let existingRaw = try? KeychainStore.get(namespace: namespace, key: key) else { return }
        guard let envelope = decodeEnvelope(existingRaw) else {
            if tags.isEmpty {
                try KeychainStore.delete(namespace: namespace, key: key)
            }
            return
        }
        let remaining = envelope.variants.filter { $0.tags != tags }
        if remaining.isEmpty {
            try KeychainStore.delete(namespace: namespace, key: key)
        } else {
            let updated = SecretEnvelope(secretsVaultVariants: true, description: envelope.description, variants: remaining)
            try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(updated))
        }
    }

    /// Labels for every variant stored under one key — used by `secrets list NAMESPACE KEY`.
    static func listVariants(namespace: String, key: String) throws -> [String] {
        let raw = try KeychainStore.get(namespace: namespace, key: key)
        guard let envelope = decodeEnvelope(raw) else { return ["(untagged)"] }
        return envelope.variants.map { canonicalLabel($0.tags) }.sorted()
    }

    /// A one-line human-readable note on what a key IS, independent of which
    /// tagged variant — e.g. "MongoDB connection string for the primary db".
    /// Applies to the whole key, not per-variant, since tags already describe
    /// how variants differ.
    static func setDescription(namespace: String, key: String, description: String) throws {
        let existingRaw = try? KeychainStore.get(namespace: namespace, key: key)

        if let existingRaw, let envelope = decodeEnvelope(existingRaw) {
            let updated = SecretEnvelope(secretsVaultVariants: true, description: description, variants: envelope.variants)
            try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(updated))
            return
        }

        guard let existingRaw else {
            throw TaggedSecretError.noValueYet
        }
        // Upgrade a plain legacy value into an envelope so it has somewhere
        // to carry the description, keeping it as the sole untagged variant.
        let envelope = SecretEnvelope(secretsVaultVariants: true, description: description,
                                       variants: [SecretVariant(tags: [:], value: existingRaw)])
        try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(envelope))
    }

    static func getDescription(namespace: String, key: String) -> String? {
        guard let raw = try? KeychainStore.get(namespace: namespace, key: key) else { return nil }
        return decodeEnvelope(raw)?.description
    }
}
