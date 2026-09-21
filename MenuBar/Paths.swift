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

    /// Finds a Python that actually runs.
    ///
    /// Existence is not enough: on a Mac without the Command Line Tools,
    /// /usr/bin/python3 is a stub that pops a download prompt and blocks, so
    /// each candidate is executed with a timeout and judged on its output.
    static func findPython() -> String? {
        if let cached = cachedPython { return cached }
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
