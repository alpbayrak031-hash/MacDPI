import Foundation

/// Sets up the launchd jobs. The engine and the menu bar are separate jobs so
/// that quitting the menu bar never takes your browsing down with it.
enum Installer {
    static func installEngineAgent(port: Int = 8881, transparent: Bool = false) {
        guard let python = Paths.findPython() else { return }
        try? FileManager.default.createDirectory(
            atPath: Paths.stateDir, withIntermediateDirectories: true)
        var args = [
            python, "-m", "macdpi",
            "--port", String(port),
            // Wait for a route at login instead of failing lookups in a burst.
            "--wait-for-network", "300",
        ]
        if transparent {
            // Also open the transparent listeners the pf redirect feeds.
            args.append("--transparent")
        }
        LaunchAgent.write(
            label: LaunchAgent.engineLabel,
            programArguments: args,
            workingDirectory: Paths.engineDir,
            logPath: Paths.logPath,
            keepAlive: true,
            highFileLimit: true)
    }

    /// Whether the installed engine agent currently carries --transparent.
    static func engineAgentIsTransparent() -> Bool {
        let url = LaunchAgent.plistURL(LaunchAgent.engineLabel)
        guard let data = try? Data(contentsOf: url),
              let job = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any],
              let args = job["ProgramArguments"] as? [String]
        else { return false }
        return args.contains("--transparent")
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

    /// The agent embeds the app's path, so a moved or replaced app leaves a
    /// stale job behind. Rewrite it whenever it no longer matches.
    static func repairIfMoved() {
        guard LaunchAgent.isInstalled(LaunchAgent.engineLabel) else { return }
        let url = LaunchAgent.plistURL(LaunchAgent.engineLabel)
        guard let data = try? Data(contentsOf: url),
              let job = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any],
              let workingDirectory = job["WorkingDirectory"] as? String
        else { return }

        if workingDirectory != Paths.engineDir {
            // Preserve whether "all apps" was on when rewriting the moved agent.
            installEngineAgent(transparent: engineAgentIsTransparent())
            if !LaunchAgent.reload(LaunchAgent.engineLabel) {
                // One more go: leaving no job loaded while the system proxy is
                // on would take every browser down with it.
                Thread.sleep(forTimeInterval: 2)
                LaunchAgent.reload(LaunchAgent.engineLabel)
            }
        }
        if LaunchAgent.isInstalled(LaunchAgent.barLabel) {
            let barURL = LaunchAgent.plistURL(LaunchAgent.barLabel)
            if let barData = try? Data(contentsOf: barURL),
               let barJob = try? PropertyListSerialization.propertyList(
                    from: barData, options: [], format: nil) as? [String: Any],
               let arguments = barJob["ProgramArguments"] as? [String],
               arguments.first != Bundle.main.executablePath {
                installMenuBarAgent()
            }
        }
    }
}
