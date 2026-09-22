import Foundation

struct Request: Codable {
    let op: String
    let namespace: String?
    let key: String?
    let value: String?
}

struct Response: Codable {
    let ok: Bool
    let value: String?
    let keys: [String]?
    let locked: Bool?
    let error: String?
}
