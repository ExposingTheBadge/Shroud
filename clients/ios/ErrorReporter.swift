//
//  ErrorReporter.swift
//  SHROUD — anonymous error reporting (iOS + macOS).
//
//  Hooks NSSetUncaughtExceptionHandler + a Swift signal handler. Builds
//  a PII-scrubbed report, seals it to the operator's diagnostics
//  pubkey using AnonRouting.seal, posts to /api/v1/diagnostics/report.
//
//  Wire format matches crypto/error_reporting.py byte-for-byte.
//

import Foundation
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

public enum ErrorReporter {

    private static let schema = "shroud.diag.v1"
    private static let appVersion = "2.5.0" // keep in sync with VERSION file

    /// Operator diagnostics X25519 pubkey (32 bytes). Set via install().
    private static var operatorDiagPubkey: Data?
    private static var relayBaseURL: URL = URL(string: "https://44.202.225.57:58443")!
    private static var previousHandler: (@convention(c) (NSException) -> Void)?

    /// Call once during app launch, after the user has configured the
    /// relay URL and pinned the operator pubkey.
    public static func install(operatorPubkey: Data, baseURL: URL? = nil) {
        precondition(operatorPubkey.count == 32, "operator pubkey must be 32 bytes")
        self.operatorDiagPubkey = operatorPubkey
        if let u = baseURL { self.relayBaseURL = u }

        previousHandler = NSGetUncaughtExceptionHandler()
        NSSetUncaughtExceptionHandler { exception in
            ErrorReporter.handleNSException(exception)
            // Chain to previous handler so the OS still terminates the
            // process the way it would normally.
            ErrorReporter.previousHandler?(exception)
        }

        // Also catch fatal Swift errors via signal handler.
        signal(SIGABRT, ErrorReporter.signalHandler)
        signal(SIGSEGV, ErrorReporter.signalHandler)
        signal(SIGBUS,  ErrorReporter.signalHandler)
        signal(SIGILL,  ErrorReporter.signalHandler)
        signal(SIGFPE,  ErrorReporter.signalHandler)
    }

    /// Non-fatal log report. Best-effort; never blocks the caller.
    public static func log(_ message: String, extra: [String: String] = [:]) {
        DispatchQueue.global(qos: .background).async {
            let report = buildReport(
                kind: "log", message: message, stack: "", extra: extra
            )
            _ = submit(report)
        }
    }

    // MARK: - Internals

    private static func handleNSException(_ exc: NSException) {
        let message = exc.reason ?? exc.name.rawValue
        let stack = (exc.callStackSymbols).joined(separator: "\n")
        let report = buildReport(
            kind: "crash",
            message: message,
            stack: stack,
            extra: ["exception_name": exc.name.rawValue]
        )
        _ = submit(report)
    }

    private static let signalHandler: @convention(c) (Int32) -> Void = { signo in
        let trace = Thread.callStackSymbols.joined(separator: "\n")
        let report = ErrorReporter.buildReport(
            kind: "crash",
            message: "fatal signal \(signo)",
            stack: trace,
            extra: ["signal": String(signo)]
        )
        _ = ErrorReporter.submit(report)
        // Restore default handler and re-raise so the OS can dump core.
        signal(signo, SIG_DFL)
        raise(signo)
    }

    private static func buildReport(
        kind: String, message: String, stack: String, extra: [String: String]
    ) -> [String: Any] {
        let ts = Int(Date().timeIntervalSince1970)
        #if canImport(UIKit)
        let os = "iOS \(UIDevice.current.systemVersion)"
        let app = "shroud-ios"
        #elseif canImport(AppKit)
        let os = "macOS \(ProcessInfo.processInfo.operatingSystemVersionString)"
        let app = "shroud-macos"
        #else
        let os = "unknown"
        let app = "shroud-swift"
        #endif

        var ctx: [String: String] = [:]
        for (k, v) in extra { ctx[k] = scrub(v) }

        return [
            "schema":      schema,
            "ts":          ts,
            "app":         app,
            "app_version": appVersion,
            "os":          os,
            "kind":        kind,
            "message":     scrub(message),
            "stack":       scrub(stack),
            "context":     ctx,
        ]
    }

    private static func submit(_ report: [String: Any]) -> Bool {
        guard let opPub = operatorDiagPubkey, opPub.contains(where: { $0 != 0 }) else {
            return false
        }

        guard let payload = try? JSONSerialization.data(
            withJSONObject: report,
            options: [.sortedKeys]
        ) else { return false }

        let sealed: Data
        do {
            sealed = try AnonRouting.seal(payload: payload, recipientPub: opPub)
        } catch {
            return false
        }
        guard sealed.count <= 4096 else { return false }
        var padded = sealed
        padded.append(Data(repeating: 0, count: 4096 - sealed.count))

        let tag = AnonRouting.routingTag(
            sharedRoot: opPub,
            pair: 0,
            epoch: AnonRouting.epochFor()
        )
        let tagHex = tag.map { String(format: "%02x", $0) }.joined()

        var req = URLRequest(url: relayBaseURL.appendingPathComponent("/api/v1/diagnostics/report"))
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.setValue(tagHex, forHTTPHeaderField: "X-Routing-Tag")
        req.timeoutInterval = 5

        // Synchronous submit; we're typically called from a crash
        // handler where we want to finish before the process dies.
        let sem = DispatchSemaphore(value: 0)
        var success = false
        let task = URLSession.shared.uploadTask(with: req, from: padded) { _, resp, _ in
            if let http = resp as? HTTPURLResponse,
               (200..<300).contains(http.statusCode) {
                success = true
            }
            sem.signal()
        }
        task.resume()
        _ = sem.wait(timeout: .now() + 5)
        return success
    }

    // MARK: - PII scrubber

    private static let patterns: [(NSRegularExpression, String)] = {
        func r(_ pat: String) -> NSRegularExpression {
            return try! NSRegularExpression(pattern: pat)
        }
        return [
            (r("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b"), "<UUID>"),
            (r("\\b[0-9a-fA-F]{24,}\\b"), "<HEX>"),
            (r("\\b[\\w.+-]+@[\\w.-]+\\.\\w+\\b"), "<EMAIL>"),
            (r("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"), "<IPV4>"),
            (r("\\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\\b"), "<IPV6>"),
            (r("(/(?:home|Users)/)[^/\\s\"']+"), "$1<USER>"),
            (r("(/var/mobile/Containers/Data/Application/)[^/]+"), "$1<APP>"),
            (r("\\beyJ[\\w-]+\\.[\\w-]+\\.[\\w-]+\\b"), "<JWT>"),
            (r("\\+?\\d[\\d\\s().-]{7,}\\d"), "<PHONE>"),
        ]
    }()

    private static func scrub(_ s: String) -> String {
        if s.isEmpty { return s }
        var out = s
        for (regex, replacement) in patterns {
            out = regex.stringByReplacingMatches(
                in: out,
                range: NSRange(out.startIndex..., in: out),
                withTemplate: replacement
            )
        }
        return out
    }
}
