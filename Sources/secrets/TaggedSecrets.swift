import Foundation

/// One tagged value under a key — e.g. tags ["environment": "production",
/// "app": "web"] for a MONGODB_URI that differs per environment/app.
/// Empty tags is the untagged/default variant.
struct SecretVariant: Codable, Equatable {
    let tags: [String: String]
    let value: String
}

/// The on-disk shape for a key that has ever been overwritten, tagged, or
/// described. Marked with its own flag so a plain legacy value (a key set
/// once and never touched again) is never mistaken for one — a legacy value
/// is just a raw string, not JSON, so decoding this struct from it fails and
/// callers treat it as a single untagged value with no description. That's
/// what keeps every already-migrated secret working unchanged.
///
/// `previous` is the variant the most recent `set` overwrote, kept so one
/// mistaken overwrite — a wrong value piped to the wrong key — isn't an
/// irreversible loss. One level only; the next overwrite replaces it.
struct SecretEnvelope: Codable {
    var secretsVaultVariants: Bool
    var description: String?
    var variants: [SecretVariant]
    var previous: SecretVariant?
}

enum TaggedSecretError: Error, CustomStringConvertible {
    case noVariantForTags(available: [[String: String]])
    case noValueYet
    case corruptEnvelope
    case nothingToUndo

    var description: String {
        switch self {
        case .noVariantForTags(let available):
            return "no variant stored for those tags. Available: \(TaggedSecrets.describe(available))"
        case .noValueYet:
            return "no value stored for this key yet — `secrets set` it before describing it"
        case .corruptEnvelope:
            return "stored value is marked as a variants envelope but can't be decoded — refusing to return or overwrite it"
        case .nothingToUndo:
            return "nothing to undo — this key has no overwritten value on record"
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

    private static let envelopeMarker = "\"secretsVaultVariants\""

    /// nil means "a plain legacy value". A value that carries the envelope
    /// marker but doesn't decode is an error, never a plain value: returning
    /// it raw would hand the caller the JSON of EVERY variant — production
    /// included — in answer to a request that named none of them, and
    /// overwriting it would destroy all of them. A future schema change that
    /// broke decoding of old envelopes would have done exactly that silently.
    private static func loadEnvelope(_ raw: String) throws -> SecretEnvelope? {
        guard let data = raw.data(using: .utf8) else { return nil }
        if let envelope = try? JSONDecoder().decode(SecretEnvelope.self, from: data), envelope.secretsVaultVariants {
            return envelope
        }
        if raw.contains(envelopeMarker) {
            throw TaggedSecretError.corruptEnvelope
        }
        return nil
    }

    private static func encodeEnvelope(_ envelope: SecretEnvelope) throws -> String {
        let data = try JSONEncoder().encode(envelope)
        return String(data: data, encoding: .utf8)!
    }

    private static func write(_ envelope: SecretEnvelope, namespace: String, key: String) throws {
        try KeychainStore.set(namespace: namespace, key: key, value: try encodeEnvelope(envelope))
    }

    static func get(namespace: String, key: String, tags: [String: String]) throws -> String {
        let raw = try KeychainStore.get(namespace: namespace, key: key)
        guard let envelope = try loadEnvelope(raw) else {
            // Legacy plain value: it IS the untagged variant. A caller that
            // explicitly asked for tags is asking for something this key
            // doesn't have, and must not be handed the untagged value instead.
            if tags.isEmpty { return raw }
            throw TaggedSecretError.noVariantForTags(available: [[:]])
        }
        if let match = envelope.variants.first(where: { $0.tags == tags }) {
            return match.value
        }
        // With no tags asked for and exactly one variant stored there is
        // nothing to disambiguate, so it's returned. But tags that were asked
        // for and don't match are never waved through, single variant or not:
        // `get KEY environment=production` handing back the only variant —
        // which happens to be development's — is precisely the silent
        // wrong-environment failure tags exist to make impossible.
        if tags.isEmpty, envelope.variants.count == 1 {
            return envelope.variants[0].value
        }
        throw TaggedSecretError.noVariantForTags(available: envelope.variants.map { $0.tags })
    }

    static func set(namespace: String, key: String, tags: [String: String], value: String) throws {
        let existingRaw = try? KeychainStore.get(namespace: namespace, key: key)
        let incoming = SecretVariant(tags: tags, value: value)

        guard let existingRaw else {
            // First value for this key. Untagged stays a plain string, exactly
            // like every secret set before envelopes existed.
            if tags.isEmpty {
                try KeychainStore.set(namespace: namespace, key: key, value: value)
            } else {
                try write(SecretEnvelope(secretsVaultVariants: true, description: nil, variants: [incoming], previous: nil),
                          namespace: namespace, key: key)
            }
            return
        }

        if var envelope = try loadEnvelope(existingRaw) {
            if let overwritten = envelope.variants.first(where: { $0.tags == tags }) {
                envelope.previous = overwritten
            }
            envelope.variants.removeAll { $0.tags == tags }
            envelope.variants.append(incoming)
            try write(envelope, namespace: namespace, key: key)
            return
        }

        // Legacy plain value. Overwriting it (no tags) keeps the old value as
        // `previous`; adding a tagged variant beside it keeps it as the
        // untagged variant. Either way it's an envelope from here on.
        let legacy = SecretVariant(tags: [:], value: existingRaw)
        let envelope = tags.isEmpty
            ? SecretEnvelope(secretsVaultVariants: true, description: nil, variants: [incoming], previous: legacy)
            : SecretEnvelope(secretsVaultVariants: true, description: nil, variants: [incoming, legacy], previous: nil)
        try write(envelope, namespace: namespace, key: key)
    }

    /// Puts back the variant the last `set` overwrote. One level: the value
    /// being undone is discarded, not kept as a new `previous`.
    static func undo(namespace: String, key: String) throws {
        let raw = try KeychainStore.get(namespace: namespace, key: key)
        guard var envelope = try loadEnvelope(raw), let previous = envelope.previous else {
            throw TaggedSecretError.nothingToUndo
        }
        envelope.variants.removeAll { $0.tags == previous.tags }
        envelope.variants.append(previous)
        envelope.previous = nil
        try write(envelope, namespace: namespace, key: key)
    }

    static func delete(namespace: String, key: String, tags: [String: String]) throws {
        guard let existingRaw = try? KeychainStore.get(namespace: namespace, key: key) else {
            throw KeychainError.notFound
        }
        guard let envelope = try loadEnvelope(existingRaw) else {
            if tags.isEmpty {
                try KeychainStore.delete(namespace: namespace, key: key)
                return
            }
            throw TaggedSecretError.noVariantForTags(available: [[:]])
        }
        let remaining = envelope.variants.filter { $0.tags != tags }
        // A delete that matched nothing must say so. Answering "ok" to
        // `delete KEY` when the key only has tagged variants left the caller
        // believing the secret was gone.
        guard remaining.count < envelope.variants.count else {
            throw TaggedSecretError.noVariantForTags(available: envelope.variants.map { $0.tags })
        }
        if remaining.isEmpty {
            try KeychainStore.delete(namespace: namespace, key: key)
        } else {
            var updated = envelope
            updated.variants = remaining
            try write(updated, namespace: namespace, key: key)
        }
    }

    /// Labels for every variant stored under one key — used by `secrets list NAMESPACE KEY`.
    static func listVariants(namespace: String, key: String) throws -> [String] {
        let raw = try KeychainStore.get(namespace: namespace, key: key)
        guard let envelope = try loadEnvelope(raw) else { return ["(untagged)"] }
        var lines = envelope.variants.map { canonicalLabel($0.tags) }.sorted()
        if let previous = envelope.previous {
            lines.append("previous: \(canonicalLabel(previous.tags)) (undo available)")
        }
        return lines
    }

    /// A one-line human-readable note on what a key IS, independent of which
    /// tagged variant — e.g. "MongoDB connection string for the primary db".
    /// Applies to the whole key, not per-variant, since tags already describe
    /// how variants differ.
    static func setDescription(namespace: String, key: String, description: String) throws {
        let existingRaw = try? KeychainStore.get(namespace: namespace, key: key)
        guard let existingRaw else {
            throw TaggedSecretError.noValueYet
        }
        if var envelope = try loadEnvelope(existingRaw) {
            envelope.description = description
            try write(envelope, namespace: namespace, key: key)
        } else {
            // Upgrade a plain legacy value into an envelope so it has somewhere
            // to carry the description, keeping it as the sole untagged variant.
            try write(SecretEnvelope(secretsVaultVariants: true, description: description,
                                     variants: [SecretVariant(tags: [:], value: existingRaw)], previous: nil),
                      namespace: namespace, key: key)
        }
        // Mirrored into the item's comment attribute, which is what `list`
        // reads — see KeychainStore.setComment for why list must not decrypt.
        try KeychainStore.setComment(namespace: namespace, key: key, comment: description)
    }

    static func getDescription(namespace: String, key: String) -> String? {
        guard let raw = try? KeychainStore.get(namespace: namespace, key: key) else { return nil }
        return (try? loadEnvelope(raw))??.description
    }
}
