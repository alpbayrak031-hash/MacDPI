import Cocoa

/// The menu bar app's self-check: notice what is wrong with MacDPI's own setup
/// and put it right, so the user does not have to reinstall to recover.
///
/// Every fix here is one that has needed doing for real: a launch job that went
/// missing or was never loaded, an engine that is up but not answering, a
/// firewall rule pointed at listeners that are not there, DNS pointed at a DNS
/// server that is not running, a quarantine flag that stops launchd executing
/// the bundled Python, a log that grew without bound.
///
/// Two rules keep it from making things worse:
///  - It only ever does what needs no password on its own. Anything that does
///    (turning the system proxy or DNS back off) is reported, and offered once.
///  - Each fix has a budget. A fix that keeps being needed is not working, so
///    after a few tries it stops, says so, and leaves the problem visible
///    rather than looping.
final class Doctor {
    static let shared = Doctor()

    enum Level: String { case ok = "OK", fixed = "FIXED", warn = "WARNING", problem = "PROBLEM" }

    struct Finding {
        let level: Level
        let title: String
        let detail: String
    }

    /// Set by the app: plain DNS is being blocked for these names; offer the fix.
    var onOfferDNSFix: (([String]) -> Void)?
    /// Set by the app: something needs the user (a password, a reinstall).
    var onNeedsAttention: ((String) -> Void)?

    private let queue = DispatchQueue(label: "com.macdpi.doctor")
    private var timer: Timer?
    private var running = false
    private var lastUserAction = Date.distantPast
    private var fixLog: [String: [Date]] = [:]
    private var lastReport: [Finding] = []
    private var attentionShown = Set<String>()
    private var lastDNSProbe = Date.distantPast
    private(set) var recentFixes: [(Date, String)] = []

    private static let fixBudget = 3
    private static let fixWindow: TimeInterval = 15 * 60
    private static let dnsProbeEvery: TimeInterval = 5 * 60
    private static let dnsProbeEveryAuto: TimeInterval = 90
    private static let dnsAskBackoff: TimeInterval = 6 * 3600
    private static let logCap = 20 * 1024 * 1024

    // Remembered across launches.
    private let defaults = UserDefaults.standard
    private var dnsPolicyNever: Bool {
        get { defaults.bool(forKey: "macdpi.dnsfix.never") }
        set { defaults.set(newValue, forKey: "macdpi.dnsfix.never") }
    }
    /// The user has approved the DNS fix once, so it is used as an automatic
    /// fallback from then on: whenever a network blocks plain DNS, the doctor
    /// turns the fix on by itself (macOS still asks for the password, since
    /// changing DNS needs admin rights). Turning the fix off by hand clears it.
    var dnsAutoFallback: Bool {
        get { defaults.bool(forKey: "macdpi.dnsfix.auto") }
        set {
            defaults.set(newValue, forKey: "macdpi.dnsfix.auto")
            if newValue { defaults.set(false, forKey: "macdpi.dnsfix.never"); dnsAskedAt = nil }
        }
    }
    private var dnsAskedAt: Date? {
        get { defaults.object(forKey: "macdpi.dnsfix.askedAt") as? Date }
        set { defaults.set(newValue, forKey: "macdpi.dnsfix.askedAt") }
    }

    // MARK: - lifecycle

    func start() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.tick()
        }
        // First pass shortly after launch, once the engine has had a moment.
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak self] in self?.tick() }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    /// The user just did something deliberate (toggled a mode, restarted the
    /// engine). Give them room: do not fix things while they are mid-change.
    func userActed() { lastUserAction = Date() }

    /// "Don't ask again" for the automatic DNS offer.
    func neverOfferDNSFix() { dnsPolicyNever = true }
    func deferDNSOffer() { dnsAskedAt = Date() }
    func recordFix(_ what: String) { note(what) }

    var summary: String {
        if let last = recentFixes.last, Date().timeIntervalSince(last.0) < 3600 {
            let ago = Int(Date().timeIntervalSince(last.0) / 60)
            return "Fixed automatically: \(last.1) (\(ago < 1 ? "just now" : "\(ago) min ago"))"
        }
        let bad = lastReport.filter { $0.level == .problem }
        if let first = bad.first { return "Needs attention: \(first.title)" }
        return lastReport.isEmpty ? "" : "Health: all checks pass"
    }

    // MARK: - periodic pass

    private func tick() {
        guard Installer.isConfigured, !running else { return }
        guard Date().timeIntervalSince(lastUserAction) > 25 else { return }
        running = true
        queue.async { [weak self] in
            guard let self = self else { return }
            let report = self.diagnose(fix: true, deep: false)
            self.maybeOfferDNSFix()
            DispatchQueue.main.async {
                self.lastReport = report
                self.running = false
                let blocking = report.first { $0.level == .problem }
                if let blocking = blocking, !self.attentionShown.contains(blocking.title) {
                    self.attentionShown.insert(blocking.title)
                    self.onNeedsAttention?("\(blocking.title)\n\n\(blocking.detail)")
                } else if blocking == nil {
                    self.attentionShown.removeAll()
                }
            }
        }
    }

    // MARK: - the checks

    /// Run every check. With `fix`, apply the safe, passwordless repairs.
    /// `deep` adds the slower ones (code signature, stray copies) for a
    /// manually requested report.
    func diagnose(fix: Bool, deep: Bool) -> [Finding] {
        var out: [Finding] = []
        let appVersion = AppVersion.current

        // 1. The bundle itself.
        if !Paths.engineIsPresent || Paths.findPython() == nil {
            out.append(Finding(level: .problem, title: "This copy of MacDPI is incomplete",
                detail: "The engine or its bundled Python is missing from the app. "
                    + "Download MacDPI again and replace this copy."))
            return out                       // nothing below can work
        }
        let quarantine = shell("/usr/bin/xattr", ["-p", "com.apple.quarantine", Bundle.main.bundlePath])
        if !quarantine.isEmpty {
            if fix {
                shell("/usr/bin/xattr", ["-dr", "com.apple.quarantine", Bundle.main.bundlePath])
                note("cleared the download quarantine flag so macOS lets the engine run")
                out.append(Finding(level: .fixed, title: "Download quarantine flag",
                    detail: "Cleared it; macOS blocks launchd from running the bundled Python while it is set."))
            } else {
                out.append(Finding(level: .warn, title: "Download quarantine flag",
                    detail: "Set on the app; macOS may stop the engine from starting."))
            }
        }

        // 2. The launch job.
        let installed = LaunchAgent.isInstalled(LaunchAgent.engineLabel)
        let loaded = LaunchAgent.isLoaded(LaunchAgent.engineLabel)
        if !installed {
            out.append(tryFix(id: "job-missing", title: "Engine launch job was missing", fix: fix,
                detail: "Recreated it and loaded it.") { Installer.bringUpToDate(); return true })
        } else if !loaded {
            out.append(tryFix(id: "job-unloaded", title: "Engine launch job was not loaded", fix: fix,
                detail: "Loaded it.") { LaunchAgent.reload(LaunchAgent.engineLabel) })
        }

        // 3. Is the engine answering, and is it this app's version?
        var status = EngineStatus.fetch()
        if status == nil {
            let why = engineFailureHint()
            let f = tryFix(id: "engine-down", title: "The engine was not answering", fix: fix,
                           detail: "Restarted it.") {
                Installer.bringUpToDate()
                _ = LaunchAgent.reload(LaunchAgent.engineLabel)
                return Self.waitForEngine()
            }
            out.append(f.level == .problem
                ? Finding(level: .problem, title: f.title, detail: f.detail + (why.isEmpty ? "" : "\n\n" + why))
                : f)
            status = EngineStatus.fetch()
        } else if let st = status, AppVersion.isNewer(appVersion, than: st.version),
                  Installer.newerCopyInCharge() == nil {
            // Only ever upgrade: a stray older copy of the app must not keep
            // restarting a newer engine.
            out.append(tryFix(id: "engine-old", title: "Engine was an older version than the app", fix: fix,
                detail: "Restarted it on \(appVersion) (it was \(st.version)).") {
                Installer.bringUpToDate()
                _ = LaunchAgent.reload(LaunchAgent.engineLabel)
                return Self.waitForEngine()
            })
            status = EngineStatus.fetch()
        }

        // 4. The engine's own health report.
        if status != nil, let reply = Control.call(["cmd": "health"], timeout: 3),
           let health = reply["health"] as? [String: Any] {
            let checks = health["checks"] as? [[String: Any]] ?? []
            let failing = checks.filter { ($0["ok"] as? Bool) == false }
            if health["degraded"] as? Bool == true {
                let events = (health["events"] as? [String] ?? []).suffix(4).joined(separator: "\n")
                out.append(Finding(level: .problem, title: "The engine keeps failing its own checks",
                    detail: "It has restarted itself several times and a restart is not curing it, so it has "
                        + "stopped restarting. Recent events:\n\(events)"))
            } else if !failing.isEmpty {
                let names = failing.compactMap { $0["name"] as? String }.joined(separator: ", ")
                out.append(Finding(level: .warn, title: "Engine self-check is unhappy",
                    detail: "Failing: \(names). The engine will restart itself if this persists."))
            }
        }

        // 5. Settings that route traffic at the engine must have an engine behind them.
        let proxyOn = SystemProxy.isEnabled(port: status?.port ?? 8881)
        let dnsOurs = SystemDNS.isPointedAtUs()
        if status == nil, proxyOn || dnsOurs {
            let what = [proxyOn ? "the system proxy" : nil, dnsOurs ? "DNS" : nil]
                .compactMap { $0 }.joined(separator: " and ")
            out.append(Finding(level: .problem, title: "Your Mac is routed through a MacDPI that is not running",
                detail: "\(what) point at MacDPI but it is not answering, so web pages (or all name lookups) fail. "
                    + "Turn protection off from the menu, or choose Restart Engine."))
        }
        if let st = status {
            if dnsOurs && !st.dnsServer {
                out.append(tryFix(id: "dns-server", title: "DNS pointed at MacDPI but its DNS server was off", fix: fix,
                    detail: "Turned the engine's DNS server back on.") {
                    Installer.installEngineAgent(transparent: Installer.engineAgentIsTransparent(), dns: true)
                    _ = LaunchAgent.reload(LaunchAgent.engineLabel)
                    return Self.waitForEngine()
                })
            }
            if Transparent.daemonInstalled() && !st.transparent {
                out.append(tryFix(id: "pf-mismatch", title: "Firewall redirect had nothing listening", fix: fix,
                    detail: "The all-apps firewall rule was loaded but the engine had no matching listeners, "
                        + "which would drop web traffic. Restarted the engine with them.") {
                    Installer.installEngineAgent(transparent: true)
                    _ = LaunchAgent.reload(LaunchAgent.engineLabel)
                    return Self.waitForEngine()
                })
            }
        }

        // 6. Housekeeping.
        if let size = (try? FileManager.default.attributesOfItem(atPath: Paths.logPath))?[.size] as? Int,
           size > Self.logCap {
            if fix {
                Self.trimLog(Paths.logPath)
                note("trimmed the engine log (\(size / 1_048_576) MB)")
                out.append(Finding(level: .fixed, title: "Engine log was \(size / 1_048_576) MB",
                    detail: "Trimmed it to the most recent part."))
            } else {
                out.append(Finding(level: .warn, title: "Engine log is \(size / 1_048_576) MB", detail: ""))
            }
        }

        // 7. Plain DNS being blocked (reported here; the offer is made separately).
        // (The periodic pass leaves this to maybeOfferDNSFix, which paces itself.)
        if deep, status != nil, !dnsOurs, let probe = Control.call(["cmd": "dns_probe"], timeout: 12),
           let blocked = probe["blocked"] as? [String], !blocked.isEmpty {
            out.append(Finding(level: .warn, title: "This network blocks plain DNS for some sites",
                detail: "Lookups for \(blocked.joined(separator: ", ")) fail through the system resolver, so apps "
                    + "that resolve names themselves (Roblox, for one) cannot start. "
                    + (dnsAutoFallback
                        ? "MacDPI will switch its DNS fix on automatically."
                        : "\"Fix DNS for Apps That Ignore the Proxy\" in the menu fixes it.")))
        }

        // 8. Slower checks, on request only.
        if deep {
            let check = Process()
            check.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
            check.arguments = ["--verify", "--deep", "--strict", Bundle.main.bundlePath]
            check.standardOutput = Pipe(); check.standardError = Pipe()
            if (try? check.run()) != nil {
                check.waitUntilExit()
                if check.terminationStatus != 0 {
                    out.append(Finding(level: .warn, title: "The app's code signature does not verify",
                        detail: "Something inside the app was modified after it was built. It usually still "
                            + "works, but a copy of it given to another Mac may be refused. Reinstall to fix."))
                }
            }
            let copies = shell("/usr/bin/mdfind", ["kMDItemCFBundleIdentifier == 'com.macdpi.app'"])
                .split(separator: "\n").map(String.init)
                .filter { !$0.hasPrefix("/Volumes/") && $0 != Bundle.main.bundlePath }
            if !copies.isEmpty {
                out.append(Finding(level: .warn, title: "Other copies of MacDPI on this Mac",
                    detail: "An old copy opened by mistake can take over the launch jobs:\n"
                        + copies.map { "  \($0)" }.joined(separator: "\n")))
            }
        }

        if out.isEmpty {
            out.append(Finding(level: .ok, title: "Everything checks out",
                detail: "MacDPI \(appVersion), engine answering, launch job loaded."))
        }
        return out
    }

    // MARK: - automatic DNS offer

    /// If plain DNS is being blocked and the fix is not on, offer it - at most
    /// every few hours, never if the user said not to, and never silently: the
    /// change needs their password.
    private func maybeOfferDNSFix() {
        guard !dnsPolicyNever,
              Date().timeIntervalSince(lastDNSProbe)
                  > (dnsAutoFallback ? Self.dnsProbeEveryAuto : Self.dnsProbeEvery),
              !SystemDNS.isPointedAtUs(),
              EngineStatus.fetch() != nil
        else { return }
        lastDNSProbe = Date()
        if let asked = dnsAskedAt, Date().timeIntervalSince(asked) < Self.dnsAskBackoff { return }
        guard let probe = Control.call(["cmd": "dns_probe"], timeout: 12),
              let blocked = probe["blocked"] as? [String], !blocked.isEmpty
        else { return }
        DispatchQueue.main.async { [weak self] in self?.onOfferDNSFix?(blocked) }
    }

    // MARK: - report

    func reportText(_ findings: [Finding]) -> String {
        var lines = ["MacDPI \(AppVersion.current) - diagnostics", ""]
        for f in findings {
            lines.append("[\(f.level.rawValue)] \(f.title)")
            if !f.detail.isEmpty { lines.append("    " + f.detail.replacingOccurrences(of: "\n", with: "\n    ")) }
        }
        lines.append("")
        lines.append("--- engine self-check events ---")
        if let reply = Control.call(["cmd": "health"], timeout: 3),
           let health = reply["health"] as? [String: Any] {
            let uptime = Int((health["uptime"] as? Double) ?? 0)
            lines.append("uptime \(uptime)s, loop lag \(health["lag"] ?? "?")s, "
                + "\(health["fds"] ?? "?") descriptors, \(health["rss_mb"] ?? "?") MB, "
                + "restarts in the last 15 min: \(health["restarts_recent"] ?? 0)")
            for e in (health["events"] as? [String] ?? []).suffix(10) { lines.append(e) }
        } else {
            lines.append("(engine not answering)")
        }
        if !recentFixes.isEmpty {
            lines.append("")
            lines.append("--- fixed automatically ---")
            for (date, what) in recentFixes.suffix(10) {
                lines.append("\(DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .medium)): \(what)")
            }
        }
        lines.append("")
        lines.append("engine log: \(Paths.logPath)")
        return lines.joined(separator: "\n")
    }

    // MARK: - helpers

    /// Apply a fix unless its budget is spent. Returns a Finding either way.
    private func tryFix(id: String, title: String, fix: Bool, detail: String,
                        _ action: () -> Bool) -> Finding {
        guard fix else { return Finding(level: .problem, title: title, detail: "") }
        let now = Date()
        let recent = (fixLog[id] ?? []).filter { now.timeIntervalSince($0) < Self.fixWindow }
        guard recent.count < Self.fixBudget else {
            return Finding(level: .problem, title: title,
                detail: "Fixed it \(recent.count) times in the last \(Int(Self.fixWindow / 60)) minutes and "
                    + "it keeps coming back, so automatic repair has stopped. Something else is causing it.")
        }
        fixLog[id] = recent + [now]
        if action() {
            note(title.lowercased())
            return Finding(level: .fixed, title: title, detail: detail)
        }
        return Finding(level: .problem, title: title,
            detail: "Tried to fix it automatically but it did not work.")
    }

    private func note(_ what: String) {
        Self.appendEvent("app-fix", what)
        DispatchQueue.main.async { self.recentFixes.append((Date(), what)); self.recentFixes = Array(self.recentFixes.suffix(30)) }
    }

    /// Why launchd's last attempt to run the engine failed, if it did.
    private func engineFailureHint() -> String {
        let uid = getuid()
        let info = shell("/bin/launchctl", ["print", "gui/\(uid)/\(LaunchAgent.engineLabel)"])
        var bits: [String] = []
        for line in info.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("last exit code") || t.hasPrefix("runs =") { bits.append(t) }
        }
        let tail = (try? String(contentsOfFile: Paths.logPath, encoding: .utf8))
            .map { String($0.suffix(600)) } ?? ""
        return (bits.joined(separator: ", ") + (tail.isEmpty ? "" : "\nLast log lines:\n" + tail))
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Same file and line format as the engine's self-check (doctor.py), so one
    /// log tells the whole story of what went wrong and what was done about it.
    private static func appendEvent(_ kind: String, _ message: String) {
        let path = (Paths.stateDir as NSString).appendingPathComponent("doctor.log")
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyy-MM-dd HH:mm:ss"
        stamp.locale = Locale(identifier: "en_US_POSIX")
        let line = "\(stamp.string(from: Date())) [\(kind)] \(message)\n"
        guard let data = line.data(using: .utf8) else { return }
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        } else {
            FileManager.default.createFile(atPath: path, contents: data)
        }
    }

    private static func waitForEngine() -> Bool {
        for _ in 0..<30 {
            if EngineStatus.fetch() != nil { return true }
            Thread.sleep(forTimeInterval: 0.5)
        }
        return false
    }

    private static func trimLog(_ path: String) {
        guard let handle = FileHandle(forUpdatingAtPath: path) else { return }
        defer { try? handle.close() }
        let keep = 256 * 1024
        let end = handle.seekToEndOfFile()
        guard end > UInt64(keep) else { return }
        handle.seek(toFileOffset: end - UInt64(keep))
        let tail = handle.readDataToEndOfFile()
        handle.truncateFile(atOffset: 0)        // launchd appends, so it follows the new end
        handle.write(tail)
    }
}
