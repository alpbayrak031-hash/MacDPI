import Cocoa

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private let menu = NSMenu()
    private var refreshTimer: Timer?

    private var status: EngineStatus?
    private var proxyOn = false
    private var port = 8881
    private var outageChecks = 0
    private var warnedAboutOutage = false

    // MARK: - lifecycle

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        menu.delegate = self
        statusItem.menu = menu

        refresh()
        if !LaunchAgent.isInstalled(LaunchAgent.engineLabel) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { self.runFirstRunSetup() }
        }

        refreshTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            self?.refresh()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTimer?.invalidate()
    }

    // MARK: - state

    private func refresh() {
        status = EngineStatus.fetch()
        port = status?.port ?? 8881
        proxyOn = SystemProxy.isEnabled(port: port)
        updateIcon()
        checkForOutage()
    }

    /// macOS is routed through a proxy that is not answering, which means no
    /// browser on this Mac can load anything. Say so, and offer the way out.
    private func checkForOutage() {
        guard proxyOn, status == nil else {
            outageChecks = 0
            warnedAboutOutage = false
            return
        }
        outageChecks += 1
        guard outageChecks >= 3, !warnedAboutOutage else { return }
        warnedAboutOutage = true

        let box = NSAlert()
        box.messageText = "MacDPI is not running"
        box.informativeText = """
        macOS is still set to route every browser through MacDPI, but its engine         is not answering - so nothing will load until this is sorted.
        """
        box.addButton(withTitle: "Restart Engine")
        box.addButton(withTitle: "Turn Protection Off")
        box.addButton(withTitle: "Ignore")
        switch box.runModal() {
        case .alertFirstButtonReturn:
            restartEngine()
        case .alertSecondButtonReturn:
            _ = SystemProxy.setEnabled(false, port: port)
            refresh()
        default:
            break
        }
    }

    private enum Health { case protected, idle, down }

    private var health: Health {
        guard status != nil else { return .down }
        return proxyOn ? .protected : .idle
    }

    private func updateIcon() {
        guard let button = statusItem.button else { return }
        let (symbol, description, tip): (String, String, String) = {
            switch health {
            case .protected:
                return ("lock.shield.fill", "MacDPI protecting",
                        "MacDPI: protecting every browser")
            case .idle:
                return ("lock.shield", "MacDPI idle",
                        "MacDPI: running, but macOS is not routed through it")
            case .down:
                return ("exclamationmark.shield", "MacDPI stopped",
                        "MacDPI: the engine is not running")
            }
        }()
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: description)
        image?.isTemplate = true
        button.image = image
        button.toolTip = tip
    }

    // MARK: - menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        refresh()
        menu.removeAllItems()

        switch health {
        case .protected: addHeader("Protecting every browser")
        case .idle:      addHeader("Engine running — not routed")
        case .down:      addHeader("Engine not running")
        }

        if let status {
            addDetail("\(status.active) active · \(status.connections) connections"
                      + (status.failed > 0 ? " · \(status.failed) failed" : ""))
            addDetail("↑ \(format(status.bytesUp))   ↓ \(format(status.bytesDown))")
            if let doh = status.doh { addDetail("DNS over HTTPS: \(doh)") }
            addDetail("\(status.learnedCount) sites learned · up \(formatUptime(status.uptime))")
            if status.transparent && Transparent.daemonInstalled() {
                addDetail("Covering all apps"
                          + (status.bypassCount > 0 ? " · \(status.bypassCount) excluded" : ""))
            }
        }

        menu.addItem(.separator())

        if let st = status {
            let toggle = NSMenuItem(
                title: proxyOn ? "Turn Protection Off" : "Turn Protection On",
                action: #selector(toggleProtection), keyEquivalent: "")
            toggle.target = self
            menu.addItem(toggle)

            let allAppsOn = st.transparent && Transparent.daemonInstalled()
            let allApps = NSMenuItem(title: "Cover All Apps, Not Just Browsers",
                                     action: #selector(toggleAllApps), keyEquivalent: "")
            allApps.target = self
            allApps.state = allAppsOn ? .on : .off
            menu.addItem(allApps)
            if allAppsOn {
                let excl = NSMenuItem(
                    title: st.bypassCount > 0
                        ? "Excluded Sites (\(st.bypassCount))…"
                        : "Excluded Sites…",
                    action: #selector(editExclusions), keyEquivalent: "")
                excl.target = self
                menu.addItem(excl)
            }

            menu.addItem(strategyMenuItem())
            menu.addItem(recentMenuItem())
        } else {
            let start = NSMenuItem(title: "Start Engine",
                                   action: #selector(startEngine), keyEquivalent: "")
            start.target = self
            menu.addItem(start)
        }

        menu.addItem(.separator())
        addAction("Test This Network…", #selector(runNetworkTest))
        if status != nil {
            addAction("Flush DNS Cache", #selector(flushDNS))
            addAction("Forget Learned Strategies", #selector(forgetLearned))
        }
        addAction("Open Log", #selector(openLog))
        addAction("Restart Engine", #selector(restartEngine))

        menu.addItem(.separator())
        let login = NSMenuItem(title: "Start at Login",
                               action: #selector(toggleLoginItem), keyEquivalent: "")
        login.target = self
        login.state = LaunchAgent.isInstalled(LaunchAgent.barLabel) ? .on : .off
        menu.addItem(login)
        addAction("Remove MacDPI…", #selector(uninstall))

        menu.addItem(.separator())
        addAction("Quit MacDPI", #selector(quit))
    }

    private func addHeader(_ text: String) {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [.font: NSFont.systemFont(ofSize: 13, weight: .semibold)])
        item.isEnabled = false
        menu.addItem(item)
    }

    private func addDetail(_ text: String) {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [.font: NSFont.menuFont(ofSize: 11),
                         .foregroundColor: NSColor.secondaryLabelColor])
        item.isEnabled = false
        menu.addItem(item)
    }

    private func addAction(_ title: String, _ selector: Selector) {
        let item = NSMenuItem(title: title, action: selector, keyEquivalent: "")
        item.target = self
        menu.addItem(item)
    }

    private func strategyMenuItem() -> NSMenuItem {
        let current = status?.mode ?? "auto"
        let parent = NSMenuItem(title: "Strategy: \(current)", action: nil, keyEquivalent: "")
        let submenu = NSMenu()
        let names = ["auto", "tlsfrag", "oob", "tlsfrag+oob", "multisplit+oob",
                     "multisplit", "split", "direct"]
        for name in names {
            var title = name == "auto" ? "auto (try each, learn)" : name
            let count = status?.strategies[name] ?? 0
            let item = NSMenuItem(title: title,
                                  action: #selector(setStrategy(_:)), keyEquivalent: "")
            item.target = self
            item.representedObject = name
            item.state = (name == current) ? .on : .off
            if count > 0 {
                // Badges only exist on Sonoma and later; older systems get the
                // count in the title rather than losing the information.
                if #available(macOS 14, *) {
                    item.badge = NSMenuItemBadge(count: count)
                } else {
                    title += "  (\(count))"
                    item.title = title
                }
            }
            submenu.addItem(item)
        }
        parent.submenu = submenu
        return parent
    }

    private func recentMenuItem() -> NSMenuItem {
        let parent = NSMenuItem(title: "Recent Sites", action: nil, keyEquivalent: "")
        let submenu = NSMenu()
        let reply = Control.call(["cmd": "recent", "limit": 20])
        let entries = (reply?["recent"] as? [[String: Any]] ?? []).reversed()
        if entries.isEmpty {
            let empty = NSMenuItem(title: "Nothing yet", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            submenu.addItem(empty)
        }
        for entry in entries {
            let host = entry["host"] as? String ?? "?"
            let strategy = entry["strategy"] as? String ?? "?"
            let item = NSMenuItem(title: "\(host)  —  \(strategy)", action: nil, keyEquivalent: "")
            item.isEnabled = false
            submenu.addItem(item)
        }
        parent.submenu = submenu
        return parent
    }

    // MARK: - formatting

    private func format(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    private func formatUptime(_ seconds: Double) -> String {
        let total = Int(seconds)
        if total < 60 { return "\(total)s" }
        if total < 3600 { return "\(total / 60)m" }
        if total < 86400 { return "\(total / 3600)h \((total % 3600) / 60)m" }
        return "\(total / 86400)d \((total % 86400) / 3600)h"
    }

    // MARK: - actions

    @objc private func toggleProtection() {
        let wanted = !proxyOn
        if wanted && status == nil {
            alert("The engine is not running",
                  "Start the engine first, then turn protection on.")
            return
        }
        if SystemProxy.setEnabled(wanted, port: port) {
            refresh()
        }
    }

    @objc private func toggleAllApps() {
        let currentlyOn = (status?.transparent ?? false) && Transparent.daemonInstalled()
        if currentlyOn {
            disableAllApps()
        } else {
            enableAllApps()
        }
    }

    private func enableAllApps() {
        let intro = NSAlert()
        intro.messageText = "Cover every app?"
        intro.informativeText = """
        This redirects all app traffic on ports 80 and 443 through MacDPI using \
        the macOS firewall — not just browsers. You'll be asked for your password \
        once to load the firewall rule, and it will reload itself at every boot.

        A handful of non-web services use these ports too; if something \
        misbehaves you can exclude it, or turn this off again. Private and local \
        addresses are never touched.
        """
        intro.addButton(withTitle: "Continue")
        intro.addButton(withTitle: "Cancel")
        guard intro.runModal() == .alertFirstButtonReturn else { return }

        // 1. Engine must be listening transparently before pf points at it.
        Installer.installEngineAgent(transparent: true)
        guard LaunchAgent.reload(LaunchAgent.engineLabel), waitForEngine() else {
            revertEnginePlain()
            alert("Could not start transparent mode",
                  "The engine did not come back up. Nothing was changed in the firewall.")
            return
        }

        // 2. Get the ruleset the engine generated for the current exclusions.
        guard let reply = Control.call(["cmd": "pf_ruleset"], timeout: 5),
              let ruleset = reply["ruleset"] as? String, !ruleset.isEmpty else {
            revertEnginePlain()
            alert("Could not build the firewall rules",
                  "The engine did not return a ruleset. Nothing was changed.")
            return
        }

        // 3. Load pf (the password prompt). Cancel → roll the engine back.
        guard Transparent.enable(ruleset: ruleset) else {
            revertEnginePlain()
            return   // user likely cancelled the password prompt
        }

        // 4. Prove the redirect actually captures this Mac's own traffic.
        let selftest = Control.call(["cmd": "selftest", "timeout": 5], timeout: 8)
        let captured = (selftest?["captured"] as? Bool) ?? false
        if captured {
            refresh()
            alert("All apps are covered",
                  "Every app's web traffic now goes through MacDPI. Turn this off "
                  + "or exclude specific sites any time from the menu.")
        } else {
            // Fail safe: undo everything rather than leave traffic black-holed.
            _ = Transparent.disable()
            revertEnginePlain()
            alert("Transparent mode didn't take effect",
                  "The firewall redirect didn't capture a test connection, so "
                  + "MacDPI rolled the change back to keep your network working. "
                  + "Browsers are still covered as before. This can happen if "
                  + "another firewall or VPN owns pf.")
        }
    }

    private func disableAllApps() {
        guard Transparent.disable() else { return }   // cancelled password
        revertEnginePlain()
        refresh()
        alert("Back to browsers only",
              "The firewall redirect is removed and your normal pf rules are "
              + "restored. Browsers are still protected through the system proxy.")
    }

    /// Rewrite the engine agent without --transparent and reload it.
    private func revertEnginePlain() {
        Installer.installEngineAgent(transparent: false)
        _ = LaunchAgent.reload(LaunchAgent.engineLabel)
        _ = waitForEngine()
    }

    @objc private func editExclusions() {
        let current = (Control.call(["cmd": "get_bypass"])?["bypass"] as? [String]) ?? []
        let box = NSAlert()
        box.messageText = "Excluded sites"
        box.informativeText = "One host, IP, or CIDR per line. These bypass MacDPI "
            + "entirely — use it for anything that breaks when routed, like a bank "
            + "or a work VPN. Private and local addresses are always excluded."
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 380, height: 200))
        let text = NSTextView(frame: scroll.bounds)
        text.string = current.joined(separator: "\n")
        text.isEditable = true
        text.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        text.isAutomaticQuoteSubstitutionEnabled = false
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        box.accessoryView = scroll
        box.addButton(withTitle: "Save")
        box.addButton(withTitle: "Cancel")
        guard box.runModal() == .alertFirstButtonReturn else { return }

        let entries = text.string
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        _ = Control.call(["cmd": "set_bypass", "bypass": entries])

        // Regenerate and reload the firewall rules with the new exclusions.
        if let reply = Control.call(["cmd": "pf_ruleset"], timeout: 5),
           let ruleset = reply["ruleset"] as? String, !ruleset.isEmpty {
            _ = Transparent.reloadRules(ruleset: ruleset)
        }
        refresh()
    }

    @objc private func setStrategy(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String else { return }
        _ = Control.call(["cmd": "set_mode", "mode": mode])
        refresh()
    }

    @objc private func flushDNS() {
        _ = Control.call(["cmd": "flush_dns"])
    }

    @objc private func forgetLearned() {
        _ = Control.call(["cmd": "forget"])
        refresh()
    }

    @objc private func openLog() {
        NSWorkspace.shared.open(URL(fileURLWithPath: Paths.logPath))
    }

    @objc private func startEngine() {
        Installer.installEngineAgent()
        bringEngineUp()
    }

    @objc private func restartEngine() {
        bringEngineUp()
    }

    private func bringEngineUp() {
        let loaded = LaunchAgent.reload(LaunchAgent.engineLabel)
        let running = waitForEngine()
        if !running {
            let detail = loaded
                ? "The job is loaded but the engine is not answering."
                : "launchd would not load the engine job."
            showText(title: "The engine did not start",
                     body: detail + "\n\nLast lines of the log:\n\n"
                        + ((try? String(contentsOfFile: Paths.logPath, encoding: .utf8))
                            .map { String($0.suffix(2000)) } ?? "No log was written."))
        }
    }

    @discardableResult
    private func waitForEngine() -> Bool {
        for _ in 0..<30 {
            if Control.isRunning {
                refresh()
                return true
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        refresh()
        return false
    }

    @objc private func toggleLoginItem() {
        if LaunchAgent.isInstalled(LaunchAgent.barLabel) {
            LaunchAgent.remove(LaunchAgent.barLabel)
        } else {
            Installer.installMenuBarAgent()
        }
    }

    @objc private func runNetworkTest() {
        guard let python = Paths.findPython(), Paths.engineIsPresent else {
            alert("Cannot run the test",
                  "No usable Python 3 was found on this Mac.")
            return
        }
        let waiting = NSAlert()
        waiting.messageText = "Testing this network…"
        waiting.informativeText = "Trying every evasion strategy against a handful "
            + "of sites. This takes up to a minute."
        waiting.addButton(withTitle: "Cancel")

        let task = Process()
        task.executableURL = URL(fileURLWithPath: python)
        task.arguments = ["-m", "macdpi", "--test"]
        task.currentDirectoryURL = URL(fileURLWithPath: Paths.engineDir)
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()

        DispatchQueue.global().async {
            try? task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            let output = String(data: data, encoding: .utf8) ?? "(no output)"
            DispatchQueue.main.async {
                NSApp.stopModal()
                self.showText(title: "Network test", body: output)
            }
        }
        waiting.runModal()
        if task.isRunning { task.terminate() }
    }

    @objc private func uninstall() {
        let confirm = NSAlert()
        confirm.messageText = "Remove MacDPI?"
        confirm.informativeText = "This turns off the system proxy, stops the engine "
            + "and removes it from login. The app itself stays in your Applications "
            + "folder for you to delete."
        confirm.addButton(withTitle: "Remove")
        confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        if Transparent.daemonInstalled() {
            _ = Transparent.disable()
        }
        if SystemProxy.isEnabled(port: port) {
            _ = SystemProxy.setEnabled(false, port: port)
        }
        LaunchAgent.remove(LaunchAgent.engineLabel)
        LaunchAgent.remove(LaunchAgent.barLabel)
        alert("MacDPI removed", "Your network settings are back to normal.")
        NSApp.terminate(nil)
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }

    // MARK: - first run

    private func runFirstRunSetup() {
        let welcome = NSAlert()
        welcome.messageText = "Set up MacDPI"
        welcome.informativeText = """
        MacDPI runs a small proxy on this Mac and points Safari, Chrome and every \
        other browser at it, so blocked sites load in every tab.

        Setting up will:
          •  install the engine so it starts at login
          •  ask for your password once, to change the system proxy setting

        You can undo all of it later from the menu bar.
        """
        welcome.addButton(withTitle: "Set Up")
        welcome.addButton(withTitle: "Not Now")
        guard welcome.runModal() == .alertFirstButtonReturn else { return }

        guard Paths.findPython() != nil else {
            offerCommandLineTools()
            return
        }
        guard Paths.engineIsPresent else {
            alert("This copy of MacDPI is incomplete",
                  "The engine is missing from the app bundle. Download MacDPI again.")
            return
        }

        Installer.installEngineAgent()
        Installer.installMenuBarAgent()
        bringEngineUp()
        guard status != nil else { return }

        if SystemProxy.setEnabled(true, port: port) {
            refresh()
            alert("MacDPI is on",
                  "Every browser on this Mac now goes through it. "
                  + "The shield in your menu bar shows the current state.")
        } else {
            alert("Almost done",
                  "The engine is running, but the system proxy was not changed. "
                  + "Choose “Turn Protection On” from the menu bar when you are ready.")
        }
    }

    private func offerCommandLineTools() {
        let prompt = NSAlert()
        prompt.messageText = "Python 3 is needed"
        prompt.informativeText = """
        MacDPI's engine runs on Python 3, which this Mac does not have yet. \
        Apple ships it as part of the Command Line Tools.

        Install them, then open MacDPI again.
        """
        prompt.addButton(withTitle: "Install Command Line Tools")
        prompt.addButton(withTitle: "Cancel")
        if prompt.runModal() == .alertFirstButtonReturn {
            shell("/usr/bin/xcode-select", ["--install"])
        }
    }

    // MARK: - alerts

    private func alert(_ title: String, _ body: String) {
        let box = NSAlert()
        box.messageText = title
        box.informativeText = body
        box.runModal()
    }

    private func showText(title: String, body: String) {
        let box = NSAlert()
        box.messageText = title
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 620, height: 320))
        let text = NSTextView(frame: scroll.bounds)
        text.string = body
        text.isEditable = false
        text.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        box.accessoryView = scroll
        box.runModal()
    }
}
