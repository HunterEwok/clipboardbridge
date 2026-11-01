// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Foundation

/// The Rust core's one entry point (docs/core-api.md), the group's rules
/// that every member shares: JSON bytes in, JSON bytes out, through the C
/// functions of lite/ffi (lite/ffi/include/cbb_core.h). The kit asks the
/// core instead of writing the rules again in Swift.
public enum Core {
    /// The version of the request and answer shapes the kit speaks; `call`
    /// refuses a core of another.
    public static let abi = 1

    /// An error answer of the core: a stable code and name, a short message
    /// for the user and the causes under it. The app shows `message`, and
    /// `details` under it in debug mode; the log always gets both.
    public struct Refusal: Error, Equatable, Decodable, CustomStringConvertible {
        public var code: Int
        public var name: String
        public var message: String
        public var details: String?

        public var description: String {
            guard let details, !details.isEmpty else { return "core: \(message) (\(name), code \(code))" }
            return "core: \(message) (\(name), code \(code)): \(details)"
        }
    }

    /// A linked core that speaks another ABI, or an answer the kit cannot
    /// read: a build that put the wrong library in.
    public struct Mismatch: Error, Equatable, CustomStringConvertible {
        public var reason: String
        public var description: String { "core: \(reason)" }
    }

    /// The core's answer to the operation `version`.
    public struct Version: Decodable, Equatable {
        public var abi: Int
        public var core: String
        public var source: String?

        /// How `cbb version` names the core, for the apps' about screens and
        /// error reports.
        public var line: String { "core \(core), abi \(abi), source \(source ?? "unknown")" }
    }

    /// Sends one request and returns the core's answer, after checking that
    /// the core speaks `abi`. A refusal of the request is an answer with an
    /// error, not an error of `call`.
    public static func call(_ request: Data) throws -> Data {
        let got = Int(cbb_abi())
        guard got == abi else { throw Mismatch(reason: "the linked core speaks ABI \(got), not \(abi)") }
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = request.withUnsafeBytes { raw in
            cbb_call(raw.bindMemory(to: UInt8.self).baseAddress, raw.count, &count)
        }
        guard let answer else { throw Mismatch(reason: "the core gave no answer") }
        defer { cbb_free(answer, count) }
        return Data(bytes: answer, count: count)
    }

    private struct Request<A: Encodable>: Encodable {
        var abi: Int
        var op: String
        var args: A?
    }

    private struct Answer<R: Decodable>: Decodable {
        var ok: R?
        var error: Refusal?
    }

    private struct None: Codable {}

    /// Sends the operation `op` with `args` and decodes the answer's `ok`;
    /// a refusal comes back as a `Refusal`.
    public static func run<A: Encodable, R: Decodable>(_ op: String, _ args: A?, as _: R.Type = R.self) throws -> R {
        let answer = try call(JSONEncoder().encode(Request(abi: abi, op: op, args: args)))
        let a: Answer<R>
        do {
            a = try JSONDecoder().decode(Answer<R>.self, from: answer)
        } catch {
            throw Mismatch(reason: "the answer to \(op) does not read: \(error)")
        }
        if let e = a.error { throw e }
        guard let ok = a.ok else { throw Mismatch(reason: "the answer to \(op) has neither ok nor error") }
        return ok
    }

    /// Sends the operation `op`, which takes no arguments.
    public static func run<R: Decodable>(_ op: String, as _: R.Type = R.self) throws -> R {
        try run(op, Optional<None>.none, as: R.self)
    }

    /// The linked core's version, ABI and the commit it was built from.
    public static func version() throws -> Version { try run("version") }
}
