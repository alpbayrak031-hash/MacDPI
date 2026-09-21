import Foundation

/// Client for the engine's Unix control socket.
///
/// A Unix socket rather than a localhost port: a web page can reach 127.0.0.1
/// through the proxy it is already talking to, but it cannot open one of these.
enum Control {
    static let socketPath = NSHomeDirectory() + "/.macdpi/control.sock"

    static func call(_ request: [String: Any], timeout: TimeInterval = 2.0) -> [String: Any]? {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else { return nil }
        withUnsafeMutablePointer(to: &addr.sun_path) { raw in
            raw.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                for (i, byte) in pathBytes.enumerated() { dst[i] = CChar(bitPattern: byte) }
                dst[pathBytes.count] = 0
            }
        }

        let connected = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { return nil }

        guard var payload = try? JSONSerialization.data(withJSONObject: request) else { return nil }
        payload.append(0x0A)
        let written = payload.withUnsafeBytes { buffer -> Int in
            write(fd, buffer.baseAddress, buffer.count)
        }
        guard written == payload.count else { return nil }

        var response = Data()
        var chunk = [UInt8](repeating: 0, count: 8192)
        while !response.contains(0x0A) {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            response.append(contentsOf: chunk[0..<n])
        }
        guard !response.isEmpty,
              let object = try? JSONSerialization.jsonObject(with: response) as? [String: Any]
        else { return nil }
        return object
    }

    static var isRunning: Bool {
        guard let reply = call(["cmd": "ping"], timeout: 1.0) else { return false }
        return reply["ok"] as? Bool == true
    }
}

/// Snapshot of the engine, as shown in the menu.
struct EngineStatus {
    var version = ""
    var port = 8881
    var mode = "auto"
    var doh: String?
    var uptime: Double = 0
    var connections = 0
    var failed = 0
    var active = 0
    var bytesUp = 0
    var bytesDown = 0
    var learnedCount = 0
    var strategies: [String: Int] = [:]
    var transparent = false
    var bypassCount = 0

    static func fetch() -> EngineStatus? {
        guard let reply = Control.call(["cmd": "status"]),
              reply["ok"] as? Bool == true else { return nil }
        var status = EngineStatus()
        status.version = reply["version"] as? String ?? ""
        status.port = reply["port"] as? Int ?? 8881
        status.mode = reply["mode"] as? String ?? "auto"
        status.doh = reply["doh"] as? String
        status.uptime = reply["uptime"] as? Double ?? 0
        status.connections = reply["connections"] as? Int ?? 0
        status.failed = reply["failed"] as? Int ?? 0
        status.active = reply["active"] as? Int ?? 0
        status.bytesUp = reply["bytes_up"] as? Int ?? 0
        status.bytesDown = reply["bytes_down"] as? Int ?? 0
        status.learnedCount = reply["learned_count"] as? Int ?? 0
        status.strategies = reply["strategies"] as? [String: Int] ?? [:]
        status.transparent = reply["transparent"] as? Bool ?? false
        status.bypassCount = reply["bypass_count"] as? Int ?? 0
        return status
    }
}
