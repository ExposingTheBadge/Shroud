import Foundation
import Security

// Hex and little-endian helpers shared by the whole Swift client.

extension Data {
    /// Parse a hex string. Returns nil for odd length or any non-hex character.
    init?(hexString: String) {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x41...0x46: return c - 0x41 + 10
            case 0x61...0x66: return c - 0x61 + 10
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            bytes.append(hi << 4 | lo)
            i += 2
        }
        self.init(bytes)
    }

    var hexEncoded: String {
        map { String(format: "%02x", $0) }.joined()
    }

    mutating func appendLE(_ v: UInt32) {
        var le = v.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    /// Read a little-endian UInt32 at `offset` bytes from the start.
    func readLE32(at offset: Int) -> UInt32 {
        let b = Array(self[(startIndex + offset)..<(startIndex + offset + 4)])
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
    }

    /// Zero-based slice that always returns a fresh Data starting at index 0.
    func bytes(_ from: Int, _ to: Int) -> Data {
        Data(self[(startIndex + from)..<(startIndex + to)])
    }

    static func random(_ count: Int) -> Data {
        var d = Data(count: count)
        let rc = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
        return d
    }
}
