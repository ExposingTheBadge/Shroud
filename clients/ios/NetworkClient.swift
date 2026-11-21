import Foundation
import Security

// Relay HTTP lives in Relay.swift. This file keeps the Keychain wrapper.

/// Generic-password Keychain items, readable only after first unlock and
/// never synced or restored to another device.
enum KeychainStore {
    private static let service = "com.shroud.client"

    private static func base(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: key]
    }

    static func save(key: String, data: Data) {
        SecItemDelete(base(key) as CFDictionary)
        var q = base(key)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        var q = base(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else { return nil }
        return item as? Data
    }

    static func delete(key: String) {
        SecItemDelete(base(key) as CFDictionary)
    }

    static func saveString(key: String, value: String) {
        save(key: key, data: Data(value.utf8))
    }

    static func loadString(key: String) -> String? {
        load(key: key).flatMap { String(data: $0, encoding: .utf8) }
    }
}
