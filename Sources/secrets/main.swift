import Foundation

let socketDir = NSString(string: "~/Library/Application Support/secrets").expandingTildeInPath
let socketPath = socketDir + "/secrets.sock"

func printUsage() {
    print("""
    usage: secrets <command> [args]

    commands:
      unlock       authorize this session with Touch ID (or password fallback)
      lock         end the authorized session
      status       show whether the store is locked or unlocked for this caller
      get KEY      print the secret value for KEY
      set KEY      store KEY, reading its value from stdin
      delete KEY   remove KEY
      list         list stored key names (not values)
      daemon       run the background daemon (used by the LaunchAgent — don't call directly)
    """)
}

func readStdin() -> String {
    var input = ""
    while let line = Swift.readLine(strippingNewline: false) {
        input += line
    }
    if input.hasSuffix("\n") { input.removeLast() }
    return input
}

func runClient(_ request: Request) {
    do {
        let response = try sendRequest(request, socketPath: socketPath)
        if !response.ok {
            FileHandle.standardError.write("error: \(response.error ?? "unknown")\n".data(using: .utf8)!)
            exit(1)
        }
        switch request.op {
        case "get":
            print(response.value ?? "")
        case "list":
            for key in response.keys ?? [] { print(key) }
        case "status":
            print((response.locked ?? true) ? "locked" : "unlocked")
        default:
            print("ok")
        }
    } catch {
        FileHandle.standardError.write("error: \(error)\n".data(using: .utf8)!)
        exit(1)
    }
}

let arguments = CommandLine.arguments
guard arguments.count > 1 else {
    printUsage()
    exit(1)
}

switch arguments[1] {
case "daemon":
    try FileManager.default.createDirectory(atPath: socketDir, withIntermediateDirectories: true)
    let daemon = Daemon()
    let server = SocketServer(socketPath: socketPath, daemon: daemon)
    try server.run()

case "unlock":
    runClient(Request(op: "unlock", key: nil, value: nil))

case "lock":
    runClient(Request(op: "lock", key: nil, value: nil))

case "status":
    runClient(Request(op: "status", key: nil, value: nil))

case "get":
    guard arguments.count > 2 else { print("usage: secrets get KEY"); exit(1) }
    runClient(Request(op: "get", key: arguments[2], value: nil))

case "set":
    guard arguments.count > 2 else { print("usage: secrets set KEY   (value read from stdin)"); exit(1) }
    runClient(Request(op: "set", key: arguments[2], value: readStdin()))

case "delete":
    guard arguments.count > 2 else { print("usage: secrets delete KEY"); exit(1) }
    runClient(Request(op: "delete", key: arguments[2], value: nil))

case "list":
    runClient(Request(op: "list", key: nil, value: nil))

default:
    printUsage()
    exit(1)
}
