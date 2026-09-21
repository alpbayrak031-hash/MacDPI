import Foundation
import CFNetwork

/// Runs a command and returns its trimmed stdout.
@discardableResult
func shell(_ launchPath: String, _ arguments: [String]) -> String {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: launchPath)
    task.arguments = arguments
    let pipe = Pipe()
    let errorPipe = Pipe()
    task.standardOutput = pipe
    task.standardError = errorPipe
    do { try task.run() } catch { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    _ = errorPipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    return String(data: data, encoding: .utf8)?
        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
}

func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// Runs one shell command as an administrator, showing the standard macOS
/// password prompt. Returns false if the user cancels.
@discardableResult
func runPrivileged(_ command: String, reason: String) -> Bool {
    let escaped = command
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
    let source = """
    do shell script "\(escaped)" with prompt "\(reason)" with administrator privileges
    """
    var error: NSDictionary?
    NSAppleScript(source: source)?.executeAndReturnError(&error)
    return error == nil
}

enum SystemProxy {
    /// Network services that are actually enabled, as networksetup names them.
    static func services() -> [String] {
        let raw = shell("/usr/sbin/networksetup", ["-listallnetworkservices"])
        return raw.split(separator: "\n")
            .dropFirst()                                   // explanatory header
            .map(String.init)
            .filter { !$0.hasPrefix("*") }                 // disabled services
    }

    /// Whether macOS is currently routing HTTPS through our port.
    static func isEnabled(port: Int) -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?
                .takeRetainedValue() as? [String: Any] else { return false }
        let on = (settings[kCFNetworkProxiesHTTPSEnable as String] as? Int ?? 0) == 1
        let host = settings[kCFNetworkProxiesHTTPSProxy as String] as? String
        let proxyPort = settings[kCFNetworkProxiesHTTPSPort as String] as? Int
        return on && host == "127.0.0.1" && proxyPort == port
    }

    private static let bypass =
        "*.local 169.254/16 127.0.0.1 localhost ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

    static func setEnabled(_ enabled: Bool, port: Int) -> Bool {
        let names = services()
        guard !names.isEmpty else { return false }
        var parts: [String] = []
        for name in names {
            let service = shellQuote(name)
            if enabled {
                parts.append("/usr/sbin/networksetup -setwebproxy \(service) 127.0.0.1 \(port)")
                parts.append("/usr/sbin/networksetup -setsecurewebproxy \(service) 127.0.0.1 \(port)")
                parts.append("/usr/sbin/networksetup -setwebproxystate \(service) on")
                parts.append("/usr/sbin/networksetup -setsecurewebproxystate \(service) on")
                parts.append("/usr/sbin/networksetup -setproxybypassdomains \(service) \(bypass)")
            } else {
                parts.append("/usr/sbin/networksetup -setwebproxystate \(service) off")
                parts.append("/usr/sbin/networksetup -setsecurewebproxystate \(service) off")
            }
        }
        let reason = enabled
            ? "MacDPI needs your password to route this Mac through its proxy."
            : "MacDPI needs your password to restore your normal network settings."
        return runPrivileged(parts.joined(separator: "; "), reason: reason)
    }
}

/// Transparent ("all apps") interception via the pf firewall.
///
/// The engine, pf rules, and boot-time reload are three separate pieces:
///   - the engine (a user LaunchAgent) gains --transparent and its listeners;
///   - a root-owned pf ruleset redirects local :80/:443 to those listeners;
///   - a root LaunchDaemon re-applies that ruleset at every boot.
/// Only the pf steps need root, gathered into a single password prompt.
enum Transparent {
    static let rulesetPath = "/etc/macdpi/macdpi.pf"
    static let daemonPath = "/Library/LaunchDaemons/com.macdpi.pf.plist"
    static let daemonLabel = "com.macdpi.pf"
    static var stagedRuleset: String { Paths.stateDir + "/macdpi.pf.staged" }

    /// True when pf is enabled and our redirect rules are loaded.
    static func isActive() -> Bool {
        // pfctl -s rules needs root; instead infer from the daemon's presence
        // plus a live capture self-test, which the caller runs separately.
        FileManager.default.fileExists(atPath: daemonPath)
            && Installer.engineAgentIsTransparent()
    }

    static func daemonInstalled() -> Bool {
        FileManager.default.fileExists(atPath: daemonPath)
    }

    private static func daemonPlist() -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>\(daemonLabel)</string>
          <key>ProgramArguments</key>
          <array>
            <string>/sbin/pfctl</string>
            <string>-E</string>
            <string>-f</string>
            <string>\(rulesetPath)</string>
          </array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><false/>
        </dict>
        </plist>
        """
    }

    /// Load the given pf ruleset now and arrange for it at every boot.
    /// Returns false if the user cancels the password prompt or a step fails.
    static func enable(ruleset: String) -> Bool {
        // Stage both files where the engine's own user can write them, then let
        // one privileged command validate, install and load them. Nothing but
        // fixed pfctl/launchctl/cp commands ever runs as root.
        let plistTmp = Paths.stateDir + "/com.macdpi.pf.plist.staged"
        do {
            try ruleset.write(toFile: stagedRuleset, atomically: true, encoding: .utf8)
            try daemonPlist().write(toFile: plistTmp, atomically: true, encoding: .utf8)
        } catch { return false }

        // Parse-check without root before asking for a password at all.
        let check = shell("/sbin/pfctl", ["-nf", stagedRuleset])
        _ = check   // pfctl prints warnings to stderr; a real syntax error exits non-zero
        if !pfParses(stagedRuleset) { return false }

        let command = [
            "mkdir -p /etc/macdpi",
            "cp \(shellQuote(stagedRuleset)) \(rulesetPath)",
            "chown root:wheel \(rulesetPath)",
            "chmod 644 \(rulesetPath)",
            "cp \(shellQuote(plistTmp)) \(daemonPath)",
            "chown root:wheel \(daemonPath)",
            "chmod 644 \(daemonPath)",
            "/sbin/pfctl -E -f \(rulesetPath)",
        ].joined(separator: " && ")
        return runPrivileged(command,
            reason: "MacDPI needs your password to route every app through it.")
    }

    /// Reload just the ruleset (e.g. after editing exclusions), without
    /// touching the boot daemon. Assumes transparent mode is already on.
    static func reloadRules(ruleset: String) -> Bool {
        guard (try? ruleset.write(toFile: stagedRuleset, atomically: true,
                                  encoding: .utf8)) != nil else { return false }
        guard pfParses(stagedRuleset) else { return false }
        let command = [
            "cp \(shellQuote(stagedRuleset)) \(rulesetPath)",
            "chown root:wheel \(rulesetPath)",
            "/sbin/pfctl -f \(rulesetPath)",
        ].joined(separator: " && ")
        return runPrivileged(command,
            reason: "MacDPI needs your password to update the excluded sites.")
    }

    /// Remove our rules and the boot daemon, restoring Apple's default pf.
    /// pf is left enabled with the stock ruleset rather than disabled, so any
    /// other service relying on pf keeps working.
    static func disable() -> Bool {
        let command = [
            "/sbin/pfctl -f /etc/pf.conf",
            "launchctl bootout system/\(daemonLabel) 2>/dev/null || true",
            "rm -f \(daemonPath) \(rulesetPath)",
        ].joined(separator: " ; ")
        return runPrivileged(command,
            reason: "MacDPI needs your password to stop covering all apps.")
    }

    private static func pfParses(_ path: String) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        task.arguments = ["-nf", path]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        guard (try? task.run()) != nil else { return false }
        task.waitUntilExit()
        return task.terminationStatus == 0
    }
}

enum LaunchAgent {
    static let engineLabel = "com.macdpi.proxy"
    static let barLabel = "com.macdpi.menubar"

    static func plistURL(_ label: String) -> URL {
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    static func isInstalled(_ label: String) -> Bool {
        FileManager.default.fileExists(atPath: plistURL(label).path)
    }

    static func isLoaded(_ label: String) -> Bool {
        let uid = getuid()
        let out = shell("/bin/launchctl", ["print", "gui/\(uid)/\(label)"])
        return !out.isEmpty && out.contains("state =")
    }

    /// launchd caches job definitions, so a changed plist has to be booted out
    /// and bootstrapped again - kickstart alone would silently keep the old one.
    ///
    /// Both halves need patience: bootout is asynchronous, and a bootstrap that
    /// lands while the old job is still going away fails with EIO. Giving up
    /// early leaves no job at all, which with the system proxy switched on means
    /// no working browser - so this keeps trying and reports whether it worked.
    @discardableResult
    static func reload(_ label: String) -> Bool {
        let uid = getuid()
        shell("/bin/launchctl", ["bootout", "gui/\(uid)/\(label)"])
        for _ in 0..<40 {
            if !isLoaded(label) { break }
            Thread.sleep(forTimeInterval: 0.25)
        }
        for _ in 0..<15 {
            shell("/bin/launchctl", ["bootstrap", "gui/\(uid)", plistURL(label).path])
            if isLoaded(label) { return true }
            Thread.sleep(forTimeInterval: 1.0)
        }
        return isLoaded(label)
    }

    static func unload(_ label: String) {
        let uid = getuid()
        shell("/bin/launchctl", ["bootout", "gui/\(uid)/\(label)"])
    }

    static func remove(_ label: String) {
        unload(label)
        try? FileManager.default.removeItem(at: plistURL(label))
    }

    static func write(label: String, programArguments: [String],
                      workingDirectory: String?, logPath: String?,
                      keepAlive: Bool, highFileLimit: Bool = false) {
        var job: [String: Any] = [
            "Label": label,
            "ProgramArguments": programArguments,
            "RunAtLoad": true,
            "KeepAlive": keepAlive,
            "ProcessType": "Interactive",
            "ThrottleInterval": 10,
        ]
        if highFileLimit {
            // launchd's default soft limit is 256; "cover all apps" needs far
            // more. The engine also raises this itself, but setting it here
            // means the very first connections after launch are never starved.
            job["SoftResourceLimits"] = ["NumberOfFiles": 16384]
            job["HardResourceLimits"] = ["NumberOfFiles": 16384]
        }
        if let workingDirectory { job["WorkingDirectory"] = workingDirectory }
        if let logPath {
            job["StandardOutPath"] = logPath
            job["StandardErrorPath"] = logPath
        }
        let url = plistURL(label)
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let data = try? PropertyListSerialization.data(
            fromPropertyList: job, format: .xml, options: 0) {
            try? data.write(to: url)
        }
    }
}
