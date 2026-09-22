import Foundation

let socketDir = NSString(string: "~/Library/Application Support/secrets").expandingTildeInPath
let socketPath = socketDir + "/secrets.sock"

func printUsage() {
    print("""
    usage: secrets <command> <namespace> [args]

    Namespaces scope both the Keychain storage and the Touch ID grant —
    unlocking "movies" never authorizes "bitcashier", even in the same
    session. Pick one namespace per app/project (e.g. "movies", "bitcashier").

    commands:
      unlock NAMESPACE          authorize this session for NAMESPACE with Touch ID
      lock [NAMESPACE]          end authorization for NAMESPACE, or all namespaces if omitted
      status [NAMESPACE]        show unlocked namespaces, or whether one is unlocked
      get NAMESPACE KEY         print the secret value for KEY
      set NAMESPACE KEY         store KEY, reading its value from stdin
      delete NAMESPACE KEY      remove KEY
      list NAMESPACE            list stored key names in NAMESPACE (not values)
      daemon                    run the background daemon (used by the LaunchAgent — don't call directly)
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
            if request.namespace != nil {
                print((response.locked ?? true) ? "locked" : "unlocked")
            } else {
                let unlocked = response.keys ?? []
                print(unlocked.isEmpty ? "locked (no namespaces unlocked)" : "unlocked: " + unlocked.joined(separator: ", "))
            }
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
    guard arguments.count > 2 else { print("usage: secrets unlock NAMESPACE"); exit(1) }
    runClient(Request(op: "unlock", namespace: arguments[2], key: nil, value: nil))

case "lock":
    let namespace = arguments.count > 2 ? arguments[2] : nil
    runClient(Request(op: "lock", namespace: namespace, key: nil, value: nil))

case "status":
    let namespace = arguments.count > 2 ? arguments[2] : nil
    runClient(Request(op: "status", namespace: namespace, key: nil, value: nil))

case "get":
    guard arguments.count > 3 else { print("usage: secrets get NAMESPACE KEY"); exit(1) }
    runClient(Request(op: "get", namespace: arguments[2], key: arguments[3], value: nil))

case "set":
    guard arguments.count > 3 else { print("usage: secrets set NAMESPACE KEY   (value read from stdin)"); exit(1) }
    runClient(Request(op: "set", namespace: arguments[2], key: arguments[3], value: readStdin()))

case "delete":
    guard arguments.count > 3 else { print("usage: secrets delete NAMESPACE KEY"); exit(1) }
    runClient(Request(op: "delete", namespace: arguments[2], key: arguments[3], value: nil))

case "list":
    guard arguments.count > 2 else { print("usage: secrets list NAMESPACE"); exit(1) }
    runClient(Request(op: "list", namespace: arguments[2], key: nil, value: nil))

default:
    printUsage()
    exit(1)
}
