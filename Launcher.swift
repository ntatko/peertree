import AppKit
import Darwin
import Foundation

private func launchError(_ message: String) {
    let alert = NSAlert()
    alert.messageText = "PeerTree could not start"
    alert.informativeText = message
    alert.alertStyle = .warning
    alert.runModal()
}

private func appScript() -> URL? {
    let invoked = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    let resources = [Bundle.main.resourceURL, invoked.deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("Resources")]
    return resources.compactMap { $0?.appendingPathComponent("app.py") }
        .first { FileManager.default.isReadableFile(atPath: $0.path) }
}

private func execCLI(_ args: [String]) -> Never {
    let executable = "/usr/bin/python3"
    let pointers = ([executable] + args).map { strdup($0) } + [nil]
    pointers.withUnsafeBufferPointer { buffer in
        _ = execv(executable, buffer.baseAddress!)
    }
    perror(executable)
    exit(1)
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let server: Process
    let logs: Pipe

    init(script: URL, repository: URL) {
        server = Process()
        logs = Pipe()
        server.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        server.arguments = ["-B", script.path, "--repo", repository.path]
        server.standardOutput = FileHandle.nullDevice
        server.standardError = logs
        var env = ProcessInfo.processInfo.environment
        let userBrew = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/homebrew/bin").path
        env["PATH"] = [userBrew, "/opt/homebrew/bin", "/usr/local/bin", env["PATH"] ?? "/usr/bin:/bin"]
            .joined(separator: ":")
        server.environment = env
    }

    func applicationWillTerminate(_ notification: Notification) {
        if server.isRunning { server.interrupt() }
    }

    func start() throws {
        // Drain logs even while the browser UI is running.
        let recent = NSMutableData()
        logs.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
            } else {
                objc_sync_enter(recent)
                recent.append(data)
                if recent.length > 32000 {
                    recent.replaceBytes(in: NSRange(location: 0, length: recent.length - 32000),
                                        withBytes: nil, length: 0)
                }
                objc_sync_exit(recent)
            }
        }
        server.terminationHandler = { process in
            let failed = process.terminationStatus != 0
            DispatchQueue.main.async {
                if failed {
                    objc_sync_enter(recent)
                    let details = String(decoding: recent as Data, as: UTF8.self)
                    objc_sync_exit(recent)
                    launchError(details.trimmingCharacters(in: .whitespacesAndNewlines))
                }
                NSApp.terminate(nil)
            }
        }
        try server.run()
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
let launchedFromFinder = arguments.isEmpty && isatty(STDIN_FILENO) == 0 &&
    FileManager.default.currentDirectoryPath == "/"
guard let script = appScript() else {
    if launchedFromFinder { launchError("The application bundle is missing app.py.") }
    else { FileHandle.standardError.write(Data("PeerTree is missing app.py.\n".utf8)) }
    exit(1)
}

if !launchedFromFinder {
    execCLI(["-B", script.path] + arguments)
}

let application = NSApplication.shared
application.setActivationPolicy(.regular)
application.activate(ignoringOtherApps: true)
let panel = NSOpenPanel()
panel.message = "Choose a Git repository or worktree to open in PeerTree."
panel.canChooseDirectories = true
panel.canChooseFiles = false
guard panel.runModal() == .OK, let repository = panel.url else { exit(0) }

let mainMenu = NSMenu()
let item = NSMenuItem()
let appMenu = NSMenu()
appMenu.addItem(withTitle: "Quit PeerTree", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
item.submenu = appMenu
mainMenu.addItem(item)
application.mainMenu = mainMenu
let delegate = AppDelegate(script: script, repository: repository)
application.delegate = delegate
do {
    try delegate.start()
    withExtendedLifetime(delegate) { application.run() }
} catch {
    launchError(error.localizedDescription)
    exit(1)
}
