import Cocoa

// Only one menu bar instance should exist: launchd may start one at login while
// the user also opens the app from Finder.
let alreadyRunning = NSWorkspace.shared.runningApplications.contains {
    $0.bundleIdentifier == Bundle.main.bundleIdentifier
        && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
}
if alreadyRunning {
    exit(0)
}

// Strip quarantine from our own bundle. When the app is downloaded, every file
// inside it - including the bundled Python the engine runs on - is flagged
// com.apple.quarantine, and macOS would block launchd from executing that
// nested binary with no visible error. The user has already approved opening
// this app, so clearing the flag on its own contents is safe and expected.
shell("/usr/bin/xattr", ["-dr", "com.apple.quarantine", Bundle.main.bundlePath])

Installer.repairIfMoved()

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// A menu bar tool, not a windowed app: no Dock icon, no menu bar takeover.
app.setActivationPolicy(.accessory)
app.run()
