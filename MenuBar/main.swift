import Cocoa

// Only one menu bar instance should exist: launchd may start one at login while
// the user also opens the app from Finder. Bail only for a true duplicate -
// another instance running from the *same* bundle path. A copy at a different
// path (e.g. the old DMG/translocated instance that is handing off to the
// freshly installed /Applications one) is on its way out, so let this one take
// over instead of exiting into nothing.
//
// `--replace <pid>` names the one instance that does not count: an older copy
// that noticed the app had been updated underneath it, started this one, and
// is quitting (see AppDelegate.relaunchIfReplaced).
let myPath = Bundle.main.bundlePath
var replacing: pid_t = 0
if let flag = CommandLine.arguments.firstIndex(of: "--replace"),
   flag + 1 < CommandLine.arguments.count {
    replacing = pid_t(CommandLine.arguments[flag + 1]) ?? 0
}
let duplicate = NSWorkspace.shared.runningApplications.contains {
    $0.bundleIdentifier == Bundle.main.bundleIdentifier
        && $0.processIdentifier != ProcessInfo.processInfo.processIdentifier
        && $0.processIdentifier != replacing
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

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
// A menu bar tool, not a windowed app: no Dock icon, no menu bar takeover.
app.setActivationPolicy(.accessory)
app.run()
