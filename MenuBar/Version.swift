import Foundation

/// Version arithmetic for the one rule that matters when several copies of
/// the app exist on a Mac: an older copy must never displace a newer one.
enum AppVersion {
    /// This copy's version.
    static var current: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
    }

    /// The version of the app bundle at `path`, or nil if there is none there.
    static func of(bundle path: String) -> String? {
        let info = NSDictionary(contentsOfFile: path + "/Contents/Info.plist")
        return info?["CFBundleShortVersionString"] as? String
    }

    /// Whether version `a` is later than `b`. Compared numerically part by
    /// part, so 1.10.0 is later than 1.9.2.
    static func isNewer(_ a: String, than b: String) -> Bool {
        a.compare(b, options: .numeric) == .orderedDescending
    }

    /// The app bundle an engine directory (`<app>/Contents/Resources/engine`)
    /// belongs to, or nil if the path is not shaped like one.
    static func bundle(ofEngineDir dir: String) -> String? {
        let engine = URL(fileURLWithPath: dir)
        guard engine.lastPathComponent == "engine" else { return nil }
        let resources = engine.deletingLastPathComponent()
        let contents = resources.deletingLastPathComponent()
        let bundle = contents.deletingLastPathComponent()
        guard resources.lastPathComponent == "Resources",
              contents.lastPathComponent == "Contents",
              bundle.pathExtension == "app"
        else { return nil }
        return bundle.path
    }
}
