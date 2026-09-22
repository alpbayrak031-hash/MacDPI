import Cocoa

// Only one menu bar instance should exist: launchd may start one at login while
// the user also opens the app from Finder. Bail only for a true duplicate -
// another instance running from the *same* bundle path. A copy at a different
// path (e.g. the old DMG/translocated instance that is handing off to the
// freshly installed /Applications one) is on its way out, so let this one take
// over instead of exiting into nothing.
let myPath = Bundle.main.bundlePath
let duplicate = NSWorkspace.shared.runningApplications.contains {
    $0.bundleIdentifier == Bundle.main.bundleIdentifier
        && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
        && ($0.bundleURL?.path == myPath)
}
if duplicate {
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
