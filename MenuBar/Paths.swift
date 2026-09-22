import Foundation

enum Paths {
    static let stateDir = NSHomeDirectory() + "/.macdpi"
    static let logPath = stateDir + "/macdpi.log"

    /// The Python package ships inside the app bundle, so the whole thing is
    /// one draggable item with nothing to install alongside it.
    static var engineDir: String {
        Bundle.main.resourcePath.map { $0 + "/engine" } ?? ""
    }

    static var engineIsPresent: Bool {
        FileManager.default.fileExists(atPath: engineDir + "/macdpi/__main__.py")
    }

    private static var cachedPython: String?

    /// The Python runtime bundled inside the app for this Mac's architecture.
    /// A brand-new Mac has no usable system Python, so this is what normally
    /// runs the engine - nothing has to be installed.
    static var bundledPython: String? {
        guard let res = Bundle.main.resourcePath else { return nil }
        #if arch(arm64)
        let arch = "arm64"
        #else
        let arch = "x86_64"
        #endif
        let path = res + "/pyruntime/\(arch)/bin/python3"
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    /// Finds a Python that actually runs.
    ///
    /// The bundled runtime is tried first so a fresh Mac needs no dependencies.
    /// The system candidates are only a fallback (e.g. an older build with no
    /// bundled runtime): existence is not enough there, because on a Mac
    /// without the Command Line Tools /usr/bin/python3 is a stub that pops a
    /// download prompt and blocks - so each candidate is executed with a
    /// timeout and judged on its output.
    static func findPython() -> String? {
        if let cached = cachedPython { return cached }

        // The bundled runtime is our own vetted binary and is the whole reason
        // a fresh Mac needs nothing installed. If it's present, use it outright
        // - never gate it behind the runs-cleanly probe, whose failure would
        // fall through to /usr/bin/python3, which on a new Mac is the Command
        // Line Tools stub (exactly what we're avoiding).
        if let bundled = bundledPython {
            cachedPython = bundled
            return bundled
        }

        var candidates = [
            "/usr/bin/python3",
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
        ]
        let frameworks = "/Library/Frameworks/Python.framework/Versions"
        if let versions = try? FileManager.default.contentsOfDirectory(atPath: frameworks) {
            for version in versions.sorted(by: >) {
                candidates.append("\(frameworks)/\(version)/bin/python3")
            }
        }
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            if runsCleanly(path) {
                cachedPython = path
                return path
            }
        }
        return nil
    }

    private static func runsCleanly(_ path: String) -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path)
        task.arguments = ["-c", "import asyncio, ssl, socket; print('ok')"]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        guard (try? task.run()) != nil else { return false }

        let deadline = Date().addingTimeInterval(4)
        while task.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if task.isRunning {
            task.terminate()
            return false
        }
        let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(),
                            encoding: .utf8) ?? ""
        return task.terminationStatus == 0 && output.contains("ok")
    }
}
