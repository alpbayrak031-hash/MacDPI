import Foundation

/// Sets up the launchd jobs. The engine and the menu bar are separate jobs so
/// that quitting the menu bar never takes your browsing down with it.
enum Installer {
    /// The command line the engine job should run for this build of the app.
    static func engineArguments(python: String, port: Int,
                                transparent: Bool) -> [String] {
        var args = [python] + Paths.pythonOptions + [
            "-m", "macdpi",
            "--port", String(port),
            // Wait for a route at login instead of failing lookups in a burst.
            "--wait-for-network", "300",
        ]
        if transparent {
            // Also open the transparent listeners the pf redirect feeds.
            args.append("--transparent")
        }
        return args
    }

    static func installEngineAgent(port: Int = 8881, transparent: Bool = false) {
        guard let python = Paths.findPython() else { return }
        try? FileManager.default.createDirectory(
            atPath: Paths.stateDir, withIntermediateDirectories: true)
        LaunchAgent.write(
            label: LaunchAgent.engineLabel,
            programArguments: engineArguments(python: python, port: port,
                                              transparent: transparent),
            workingDirectory: Paths.engineDir,
            logPath: Paths.logPath,
            keepAlive: true,
            highFileLimit: true)
    }

    /// Marker written once setup has completed, so a later launch can tell
    /// "never set up" (do the first-run flow) from "set up, but the launchd
    /// job went missing" (silently recreate it, no reinstall, no password).
    private static var configuredMarker: String { Paths.stateDir + "/.configured" }

    static var isConfigured: Bool {
        // The marker is authoritative; the job still being installed counts too,
        // so installs that predate the marker aren't treated as brand new.
        FileManager.default.fileExists(atPath: configuredMarker)
            || LaunchAgent.isInstalled(LaunchAgent.engineLabel)
    }

    static func markConfigured() {
        try? FileManager.default.createDirectory(
            atPath: Paths.stateDir, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: configuredMarker, contents: nil)
    }

    static func clearConfigured() {
        try? FileManager.default.removeItem(atPath: configuredMarker)
    }

    private static func job(_ label: String) -> [String: Any]? {
        guard let data = try? Data(contentsOf: LaunchAgent.plistURL(label)) else {
            return nil
        }
        return (try? PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)) as? [String: Any]
    }

    /// Whether the installed engine agent currently carries --transparent.
    static func engineAgentIsTransparent() -> Bool {
        let args = job(LaunchAgent.engineLabel)?["ProgramArguments"] as? [String]
        return args?.contains("--transparent") ?? false
    }

    static func installMenuBarAgent() {
        let executable = Bundle.main.executablePath ?? ""
        guard !executable.isEmpty else { return }
        LaunchAgent.write(
            label: LaunchAgent.barLabel,
            programArguments: [executable],
            workingDirectory: nil,
            logPath: nil,
            // The menu bar is the user's own window on things: if they quit it,
            // it should stay quit until the next login.
            keepAlive: false)
    }

    /// A copy of the app newer than this one that the engine job currently
    /// runs from, or nil. A copy that finds one must step aside rather than
    /// re-point the job at itself: that re-pointing is exactly how a stray old
    /// copy, opened by mistake, quietly downgraded a working install.
    static func newerCopyInCharge() -> String? {
        guard let dir = job(LaunchAgent.engineLabel)?["WorkingDirectory"] as? String,
              dir != Paths.engineDir,
              let bundle = AppVersion.bundle(ofEngineDir: dir),
              FileManager.default.fileExists(atPath: dir + "/macdpi/__main__.py"),
              let theirs = AppVersion.of(bundle: bundle),
              AppVersion.isNewer(theirs, than: AppVersion.current)
        else { return nil }
        return bundle
    }

    /// Bring an existing install in line with this copy of the app.
    ///
    /// The engine job embeds the app's path and the engine's command line, and
    /// the engine itself is a long-lived process - so a moved app leaves a job
    /// pointing nowhere, and an app replaced in place by a newer version leaves
    /// the *old* engine running until the next login. Either way the job is
    /// rewritten if it no longer matches, and the engine restarted if it is
    /// not the version this app ships.
    static func bringUpToDate() {
        // The launchd job went missing (a past "Remove", a cleaner, a botched
        // update) but setup was done before: recreate it and load it, rather
        // than leaving the user with a dead engine they have to reinstall. This
        // is the self-heal that turns "fails to start after a reboot" into
        // "just works". No password: writing the agent and loading it are both
        // user-domain operations; the system-proxy setting persists on its own.
        if !LaunchAgent.isInstalled(LaunchAgent.engineLabel) {
            markConfigured()
            // If the pf "cover all apps" daemon is still loaded, the engine
            // must come back up WITH its transparent listeners or pf would
            // redirect traffic to ports nothing is listening on.
            installEngineAgent(transparent: Transparent.daemonInstalled())
            installMenuBarAgent()
            LaunchAgent.reload(LaunchAgent.engineLabel)
            return
        }
        guard let engine = job(LaunchAgent.engineLabel) else { return }
        markConfigured()

        // Carry over what the user had: the port, and whether "all apps" is on.
        let installed = engine["ProgramArguments"] as? [String] ?? []
        let transparent = installed.contains("--transparent")
        var port = 8881
        if let flag = installed.firstIndex(of: "--port"), flag + 1 < installed.count,
           let value = Int(installed[flag + 1]) {
            port = value
        }

        var stale = (engine["WorkingDirectory"] as? String) != Paths.engineDir
        if let python = Paths.findPython(),
           installed != engineArguments(python: python, port: port,
                                        transparent: transparent) {
            stale = true
        }
        let outdated = EngineStatus.fetch().map { $0.version != AppVersion.current } ?? false

        if stale {
            installEngineAgent(port: port, transparent: transparent)
        }
        if stale || outdated {
            if !LaunchAgent.reload(LaunchAgent.engineLabel) {
                // One more go: leaving no job loaded while the system proxy is
                // on would take every browser down with it.
                Thread.sleep(forTimeInterval: 2)
                LaunchAgent.reload(LaunchAgent.engineLabel)
            }
        }

        if let bar = job(LaunchAgent.barLabel),
           let arguments = bar["ProgramArguments"] as? [String],
           arguments.first != Bundle.main.executablePath {
            installMenuBarAgent()
        }
    }
}
