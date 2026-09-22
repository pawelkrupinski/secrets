import Darwin
import Foundation

final class SocketServer {
    private let socketPath: String
    private let daemon: Daemon
    private var listenFD: Int32 = -1

    /// Largest request line accepted. Real values are API keys, PEM blocks and
    /// small JSON blobs — nothing legitimate comes near this. It exists so a
    /// misbehaving local client can't grow the daemon's memory without bound.
    private static let maxRequestBytes = 4 * 1024 * 1024
    /// A client that connects and then never sends (or never reads) would
    /// otherwise pin a handler thread forever.
    private static let ioTimeoutSeconds = 30
    /// Beyond this many simultaneous connections, new ones are closed at once.
    /// Without a cap, a process that opens thousands and holds them exhausts
    /// the daemon's file descriptors, after which accept() fails for real
    /// clients too. Legitimate use is a handful at a time.
    private let connectionSlots = DispatchSemaphore(value: 32)

    init(socketPath: String, daemon: Daemon) {
        self.socketPath = socketPath
        self.daemon = daemon
    }

    func run() throws {
        // A client that disconnects before reading its response makes the
        // daemon's write() raise SIGPIPE, whose default action kills the
        // process — and with it every session's unlock. Any local process could
        // do that on purpose. Ignoring the signal turns that write() into a
        // plain EPIPE error, which is harmless.
        signal(SIGPIPE, SIG_IGN)

        // bind() creates the socket file with the umask applied. Setting the
        // umask first means it never exists — not even for an instant — with
        // bits another user could connect through; chmod-after-bind leaves a
        // window.
        umask(0o077)

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
        // Larger than the connection cap, so a burst is judged by the cap
        // (accepted, then closed if over) rather than refused by the kernel
        // queue before the daemon ever sees it.
        guard listen(listenFD, 64) == 0 else { throw POSIXError(.EIO) }
        log("listening on \(socketPath)")

        while true {
            let clientFD = accept(listenFD, nil, nil)
            guard clientFD >= 0 else {
                // EMFILE and friends: spinning here would peg a core while
                // the condition persists.
                usleep(50_000)
                continue
            }
            guard connectionSlots.wait(timeout: .now()) == .success else {
                close(clientFD)
                continue
            }
            DispatchQueue.global().async {
                defer { self.connectionSlots.signal() }
                self.handleClient(clientFD)
            }
        }
    }

    private func handleClient(_ fd: Int32) {
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var timeout = timeval(tv_sec: Self.ioTimeoutSeconds, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

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

    /// Returns nil on EOF before any data, on a read timeout, or on an
    /// over-long line — none of which is served.
    private func readLine(fd: Int32) -> String? {
        var buffer = [UInt8]()
        var byte: UInt8 = 0
        while true {
            let n = read(fd, &byte, 1)
            if n <= 0 { break }
            if byte == 0x0A { break }
            buffer.append(byte)
            if buffer.count > Self.maxRequestBytes { return nil }
        }
        guard !buffer.isEmpty else { return nil }
        return String(decoding: buffer, as: UTF8.self)
    }

    private func writeLine(fd: Int32, _ string: String) {
        var data = Array(string.utf8)
        data.append(0x0A)
        writeFully(fd, data)
    }
}

/// write(2) may stop short of the whole buffer on a socket; a response cut
/// off mid-JSON would read as a malformed reply rather than an error.
func writeFully(_ fd: Int32, _ bytes: [UInt8]) {
    var offset = 0
    while offset < bytes.count {
        let written = bytes.withUnsafeBufferPointer { write(fd, $0.baseAddress! + offset, bytes.count - offset) }
        if written <= 0 { return }
        offset += written
    }
}

extension SocketServer {
}
