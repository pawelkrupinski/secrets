import Darwin
import Foundation

final class SocketServer {
    private let socketPath: String
    private let daemon: Daemon
    private var listenFD: Int32 = -1

    init(socketPath: String, daemon: Daemon) {
        self.socketPath = socketPath
        self.daemon = daemon
    }

    func run() throws {
        unlink(socketPath)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { throw POSIXError(.EIO) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            let buffer = raw.bindMemory(to: Int8.self)
            for (index, byte) in pathBytes.enumerated() { buffer[index] = Int8(bitPattern: byte) }
            buffer[pathBytes.count] = 0
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, addrLen) }
        }
        guard bindResult == 0 else { throw POSIXError(.EADDRINUSE) }
        chmod(socketPath, 0o600)
        guard listen(listenFD, 8) == 0 else { throw POSIXError(.EIO) }
        log("listening on \(socketPath)")

        while true {
            let clientFD = accept(listenFD, nil, nil)
            guard clientFD >= 0 else { continue }
            DispatchQueue.global().async { self.handleClient(clientFD) }
        }
    }

    private func handleClient(_ fd: Int32) {
        defer { close(fd) }
        guard let peerPID = ProcessAncestry.peerPID(of: fd) else {
            writeLine(fd: fd, "{\"ok\":false,\"error\":\"could not read peer credentials\"}")
            return
        }
        guard let line = readLine(fd: fd) else { return }
        guard let data = line.data(using: .utf8),
              let request = try? JSONDecoder().decode(Request.self, from: data) else {
            writeLine(fd: fd, "{\"ok\":false,\"error\":\"bad request\"}")
            return
        }
        let response = daemon.handle(request, peerPID: peerPID)
        if let respData = try? JSONEncoder().encode(response),
           let respString = String(data: respData, encoding: .utf8) {
            writeLine(fd: fd, respString)
        }
    }

    private func readLine(fd: Int32) -> String? {
        var buffer = [UInt8]()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            if n <= 0 { break }
            if byte == 0x0A { break }
            buffer.append(byte)
        }
        guard !buffer.isEmpty else { return nil }
        return String(decoding: buffer, as: UTF8.self)
    }

    private func writeLine(fd: Int32, _ string: String) {
        var data = Array(string.utf8)
        data.append(0x0A)
        data.withUnsafeBufferPointer { ptr in
            _ = write(fd, ptr.baseAddress, ptr.count)
        }
    }
}
