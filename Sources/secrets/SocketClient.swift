import Darwin
import Foundation

enum ClientError: Error, CustomStringConvertible {
    case connectFailed
    case noResponse

    var description: String {
        switch self {
        case .connectFailed:
            return "could not connect to secrets daemon — is it running? (launchctl list | grep secretsd)"
        case .noResponse:
            return "daemon closed connection without responding"
        }
    }
}

func sendRequest(_ request: Request, socketPath: String) throws -> Response {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ClientError.connectFailed }
    defer { close(fd) }

    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(socketPath.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        let buffer = raw.bindMemory(to: Int8.self)
        for (index, byte) in pathBytes.enumerated() { buffer[index] = Int8(bitPattern: byte) }
        buffer[pathBytes.count] = 0
    }

    let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
    let connectResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, addrLen) }
    }
    guard connectResult == 0 else { throw ClientError.connectFailed }

    var reqBytes = try JSONEncoder().encode(request)
    reqBytes.append(0x0A)
    _ = reqBytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }

    var buffer = [UInt8]()
    var byte: UInt8 = 0
    while true {
        let n = read(fd, &byte, 1)
        if n <= 0 { break }
        if byte == 0x0A { break }
        buffer.append(byte)
    }
    guard !buffer.isEmpty else { throw ClientError.noResponse }
    return try JSONDecoder().decode(Response.self, from: Data(buffer))
}
