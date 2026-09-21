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

Installer.repairIfMoved()

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// A menu bar tool, not a windowed app: no Dock icon, no menu bar takeover.
app.setActivationPolicy(.accessory)
app.run()
