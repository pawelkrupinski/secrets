import Foundation

let socketDir = NSString(string: "~/Library/Application Support/secrets").expandingTildeInPath
// Overridable so a second daemon can run beside the LaunchAgent's -- used to
// migrate between builds and to test one before installing it. Keep it short:
// a Unix socket path is capped at 104 bytes.
let socketPath = ProcessInfo.processInfo.environment["SECRETS_SOCKET_PATH"] ?? socketDir + "/secrets.sock"

func printUsage() {
    print("""
    usage: secrets <command> <namespace> [args] [tag=value ...]

    Namespaces scope both the Keychain storage and the Touch ID grant —
    unlocking "movies" never authorizes "bitcashier", even in the same
    session. Pick one namespace per app/project (e.g. "movies", "bitcashier").

    Within a namespace, a KEY can hold multiple TAGGED VARIANTS of the same
    secret — e.g. one MONGODB_URI per environment/app. Trailing tag=value
    pairs on get/set/delete select or create a variant; omit them for the
    plain untagged value (fully backward compatible with keys that never use
    tags).

    commands:
      unlock NAMESPACE                 authorize this session for NAMESPACE with Touch ID
      lock [NAMESPACE]                 end authorization for NAMESPACE, or all namespaces if omitted
      lock-all                         panic switch: clear EVERY session's unlocks, from anywhere
      status [NAMESPACE]               show unlocked namespaces, or whether one is unlocked
      get NAMESPACE KEY [tag=value...] print the secret value for KEY (untagged, or the matching tagged variant)
      set NAMESPACE KEY [tag=value...] store KEY, reading its value from stdin
      describe NAMESPACE KEY           set/update KEY's description, reading it from stdin
      undo NAMESPACE KEY               restore the value the last `set` overwrote (one level)
      delete NAMESPACE KEY [tag=value...]  remove KEY (untagged, or one tagged variant)
      list NAMESPACE                   list stored key names in NAMESPACE, with descriptions (not values)
      list NAMESPACE KEY                list KEY's description + stored tag variants (not values)
      daemon                            run the background daemon (used by the LaunchAgent — don't call directly)

    examples:
      secrets set movies MONGODB_URI environment=production app=web <<< "mongodb://prod-web..."
      secrets set movies MONGODB_URI environment=production app=worker <<< "mongodb://prod-worker..."
      secrets describe movies MONGODB_URI <<< "Primary app database connection string"
      secrets get movies MONGODB_URI environment=production app=web
      secrets list movies MONGODB_URI
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

/// A secret typed at an interactive terminal must not echo to the screen
/// (shoulder-surfing, scrollback, terminal session recordings). Piped or
/// heredoc input isn't a tty and is read as-is.
func readSecretFromStdin() -> String {
    guard isatty(0) != 0 else { return readStdin() }
    var original = termios()
    tcgetattr(0, &original)
    var quiet = original
    quiet.c_lflag &= ~tcflag_t(ECHO)
    tcsetattr(0, TCSANOW, &quiet)
    defer {
        tcsetattr(0, TCSANOW, &original)
        FileHandle.standardError.write("\n".data(using: .utf8)!)
    }
    FileHandle.standardError.write("Enter value (input hidden; press Enter, then Ctrl-D): ".data(using: .utf8)!)
    return readStdin()
}

func parseTags(_ args: [String]) -> [String: String]? {
    var tags: [String: String] = [:]
    for arg in args {
        guard let eq = arg.firstIndex(of: "=") else { return nil }
        let key = String(arg[arg.startIndex..<eq])
        let value = String(arg[arg.index(after: eq)...])
        guard !key.isEmpty, !value.isEmpty else { return nil }
        tags[key] = value
    }
    return tags
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
    try FileManager.default.createDirectory(
        atPath: socketDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    chmod(socketDir, 0o700)
    let daemon = Daemon()
    let server = SocketServer(socketPath: socketPath, daemon: daemon)
    try server.run()

case "unlock":
    guard arguments.count > 2 else { print("usage: secrets unlock NAMESPACE"); exit(1) }
    runClient(Request(op: "unlock", namespace: arguments[2], key: nil, value: nil, tags: nil))

case "lock":
    let namespace = arguments.count > 2 ? arguments[2] : nil
    runClient(Request(op: "lock", namespace: namespace, key: nil, value: nil, tags: nil))

case "lock-all":
    runClient(Request(op: "lock-all", namespace: nil, key: nil, value: nil, tags: nil))

case "status":
    let namespace = arguments.count > 2 ? arguments[2] : nil
    runClient(Request(op: "status", namespace: namespace, key: nil, value: nil, tags: nil))

case "get":
    guard arguments.count > 3 else { print("usage: secrets get NAMESPACE KEY [tag=value ...]"); exit(1) }
    guard let tags = parseTags(Array(arguments[4...])) else { print("bad tag argument, expected key=value"); exit(1) }
    runClient(Request(op: "get", namespace: arguments[2], key: arguments[3], value: nil, tags: tags))

case "set":
    guard arguments.count > 3 else { print("usage: secrets set NAMESPACE KEY [tag=value ...]   (value read from stdin)"); exit(1) }
    guard let tags = parseTags(Array(arguments[4...])) else { print("bad tag argument, expected key=value"); exit(1) }
    runClient(Request(op: "set", namespace: arguments[2], key: arguments[3], value: readSecretFromStdin(), tags: tags))

case "describe":
    guard arguments.count > 3 else { print("usage: secrets describe NAMESPACE KEY   (description read from stdin)"); exit(1) }
    runClient(Request(op: "describe", namespace: arguments[2], key: arguments[3], value: readStdin(), tags: nil))

case "undo":
    guard arguments.count > 3 else { print("usage: secrets undo NAMESPACE KEY"); exit(1) }
    runClient(Request(op: "undo", namespace: arguments[2], key: arguments[3], value: nil, tags: nil))

case "delete":
    guard arguments.count > 3 else { print("usage: secrets delete NAMESPACE KEY [tag=value ...]"); exit(1) }
    guard let tags = parseTags(Array(arguments[4...])) else { print("bad tag argument, expected key=value"); exit(1) }
    runClient(Request(op: "delete", namespace: arguments[2], key: arguments[3], value: nil, tags: tags))

case "list":
    guard arguments.count > 2 else { print("usage: secrets list NAMESPACE [KEY]"); exit(1) }
    let key = arguments.count > 3 ? arguments[3] : nil
    runClient(Request(op: "list", namespace: arguments[2], key: key, value: nil, tags: nil))

default:
    printUsage()
    exit(1)
}
