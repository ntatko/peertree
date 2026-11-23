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

private func executablePath() -> String {
    // argv[0] is a bare name when the shell finds the Homebrew symlink on PATH.
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else { return CommandLine.arguments[0] }
    return String(cString: buffer)
}

private func appScript() -> URL? {
    let invoked = URL(fileURLWithPath: executablePath()).resolvingSymlinksInPath()
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

    init(script: URL, arguments: [String]) {
        server = Process()
        logs = Pipe()
        server.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        server.arguments = ["-B", script.path] + arguments
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
let start = NSAlert()
start.messageText = "Open a repository"
start.informativeText = "Open an existing worktree or receive a fresh clone from a paired teammate."
start.addButton(withTitle: "Open Existing")
start.addButton(withTitle: "Clone from Teammate")
start.addButton(withTitle: "Cancel")
let choice = start.runModal()
guard choice == .alertFirstButtonReturn || choice == .alertSecondButtonReturn else { exit(0) }
let cloning = choice == .alertSecondButtonReturn
let panel = NSOpenPanel()
panel.message = cloning ? "Choose or create an empty folder for the clone."
    : "Choose a Git repository or worktree to open in PeerTree."
panel.canChooseDirectories = true
panel.canChooseFiles = false
panel.canCreateDirectories = cloning
guard panel.runModal() == .OK, let repository = panel.url else { exit(0) }
var launchArguments = ["--repo", repository.path]
if cloning {
    let prompt = NSAlert()
    prompt.messageText = "Project name"
    prompt.informativeText = "Enter the project name shown on the integrator’s PeerTree window."
    let input = NSTextField(string: repository.lastPathComponent)
    input.frame.size.width = 240
    prompt.accessoryView = input
    prompt.addButton(withTitle: "Continue")
    prompt.addButton(withTitle: "Cancel")
    guard prompt.runModal() == .alertFirstButtonReturn else { exit(0) }
    let project = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !project.isEmpty else { launchError("Enter the project's name to start the clone."); exit(1) }
    launchArguments = ["clone", repository.path, "--project", project]
}

let mainMenu = NSMenu()
let item = NSMenuItem()
let appMenu = NSMenu()
appMenu.addItem(withTitle: "Quit PeerTree", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
item.submenu = appMenu
mainMenu.addItem(item)
application.mainMenu = mainMenu
let delegate = AppDelegate(script: script, arguments: launchArguments)
application.delegate = delegate
do {
    try delegate.start()
    withExtendedLifetime(delegate) { application.run() }
} catch {
    launchError(error.localizedDescription)
    exit(1)
}
