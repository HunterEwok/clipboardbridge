// SPDX-License-Identifier: AGPL-3.0-only

import Foundation

/// The service's control socket (internal/control): a JSON header line,
/// then a payload of its len bytes. The app reads the status and the
/// devices and sends and fetches the clipboard there; what changes the group
/// goes through cbb as the administrator (Admin).
enum Control {
    static let maxHeader = 64 << 10
    static let maxPayload = 1 << 20 + 64

    struct Header: Codable, Equatable {
        var op: String
        var kind: String?
        var len: Int?
        var error: String?
        var detail: String?
        var done: Bool?
        var name: String?
        var status: Status?
        var devices: [Device]?

        init(op: String, name: String? = nil) {
            self.op = op
            self.name = name
        }
    }

    /// This device and its group, as cbb status shows them.
    struct Status: Codable, Equatable {
        var device: String
        var group: String?
        var removed: Bool?
        var role: String
        var os: String?
        var away: Away?
        var version: String
    }

    /// Sync away from home on this device; nil while it is off.
    struct Away: Codable, Equatable {
        var hub: Bool?
        var hubDevice: String?
        var through: Bool?
        var error: String?
        var detail: String?

        enum CodingKeys: String, CodingKey {
            case hub, through, error, detail
            case hubDevice = "hub_device"
        }
    }

    /// A device of the group, as cbb status lists them.
    struct Device: Codable, Equatable, Identifiable {
        var id: String
        var name: String
        var role: String
        var os: String?
        /// What its hello says about its device; nil when it says nothing
        /// or is not connected.
        var form: String?
        var osVersion: String?
        var version: String?
        var mac: String?
        var admin = false
        var root = false
        var frozen = false
        var online = false
        var lastSeenMS: Int64 = 0
        var isSelf = false

        enum CodingKeys: String, CodingKey {
            case id, name, role, os, form, version, mac, admin, root, frozen, online
            case osVersion = "os_version"
            case lastSeenMS = "last_seen_ms"
            case isSelf = "self"
        }

        init(id: String, name: String, role: String = "full", os: String? = nil) {
            self.id = id
            self.name = name
            self.role = role
            self.os = os
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            id = try c.decode(String.self, forKey: .id)
            name = try c.decodeIfPresent(String.self, forKey: .name) ?? id
            role = try c.decodeIfPresent(String.self, forKey: .role) ?? "full"
            os = try c.decodeIfPresent(String.self, forKey: .os)
            form = try c.decodeIfPresent(String.self, forKey: .form)
            osVersion = try c.decodeIfPresent(String.self, forKey: .osVersion)
            version = try c.decodeIfPresent(String.self, forKey: .version)
            mac = try c.decodeIfPresent(String.self, forKey: .mac)
            admin = try c.decodeIfPresent(Bool.self, forKey: .admin) ?? false
            root = try c.decodeIfPresent(Bool.self, forKey: .root) ?? false
            frozen = try c.decodeIfPresent(Bool.self, forKey: .frozen) ?? false
            online = try c.decodeIfPresent(Bool.self, forKey: .online) ?? false
            lastSeenMS = try c.decodeIfPresent(Int64.self, forKey: .lastSeenMS) ?? 0
            isSelf = try c.decodeIfPresent(Bool.self, forKey: .isSelf) ?? false
        }
    }

    /// Why a request failed: the summary for the user, and what lies
    /// underneath, which the app shows with error details on.
    enum Failure: Error, Equatable {
        case notRunning(String)
        case denied
        case refused(String, detail: String?)
        case broken(String)
    }

    /// A message as the socket carries it.
    static func encode(_ header: Header, payload: Data = Data()) throws -> Data {
        guard payload.count <= maxPayload else { throw Failure.broken("the text is larger than 1 MiB") }
        var h = header
        h.len = payload.count
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        var data = try encoder.encode(h)
        guard data.count <= maxHeader else { throw Failure.broken("header too long") }
        data.append(UInt8(ascii: "\n"))
        data.append(payload)
        return data
    }

    /// The first message in data, and how many bytes it took; nil while
    /// data holds only a part of it.
    static func decode(_ data: Data) throws -> (Header, Data, Int)? {
        guard let newline = data.firstIndex(of: UInt8(ascii: "\n")) else {
            if data.count > maxHeader { throw Failure.broken("header too long") }
            return nil
        }
        let header: Header
        do {
            header = try JSONDecoder().decode(Header.self, from: data[data.startIndex..<newline])
        } catch {
            throw Failure.broken("bad header: \(error)")
        }
        let len = header.len ?? 0
        guard len >= 0, len <= maxPayload else { throw Failure.broken("bad payload length \(len)") }
        let start = data.index(after: newline)
        guard data.distance(from: start, to: data.endIndex) >= len else { return nil }
        let end = data.index(start, offsetBy: len)
        return (header, Data(data[start..<end]), data.distance(from: data.startIndex, to: end))
    }
}

/// One request at a time to the service, each on its own connection.
struct ControlClient {
    var path = ProcessInfo.processInfo.environment["CBB_SOCKET"] ?? "/Library/Application Support/clipboardbridge/control.sock"

    /// Sends a request and returns its single answer; an answer with an
    /// error throws Failure.refused.
    func request(_ header: Control.Header, payload: Data = Data()) async throws -> (Control.Header, Data) {
        try await withCheckedThrowingContinuation { done in
            DispatchQueue.global(qos: .userInitiated).async {
                done.resume(with: Result { try requestNow(header, payload: payload) })
            }
        }
    }

    private func requestNow(_ header: Control.Header, payload: Data) throws -> (Control.Header, Data) {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Control.Failure.broken("socket: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, [Int32(1)], socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw Control.Failure.broken("socket path too long: \(path)") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if connected != 0 {
            let e = errno
            if e == EACCES || e == EPERM { throw Control.Failure.denied }
            throw Control.Failure.notRunning("\(path): \(String(cString: strerror(e)))")
        }

        let out = try Control.encode(header, payload: payload)
        try out.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let n = Darwin.write(fd, raw.baseAddress! + sent, raw.count - sent)
                guard n > 0 else { throw Control.Failure.broken("write: \(String(cString: strerror(errno)))") }
                sent += n
            }
        }

        var data = Data()
        var chunk = [UInt8](repeating: 0, count: 16 << 10)
        while true {
            if let (answer, body, _) = try Control.decode(data) {
                if let error = answer.error { throw Control.Failure.refused(error, detail: answer.detail) }
                return (answer, body)
            }
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n == 0 { throw Control.Failure.broken("the service closed the connection") }
            if n < 0 { throw Control.Failure.broken("read: \(String(cString: strerror(errno)))") }
            data.append(contentsOf: chunk[0..<n])
        }
    }
}
