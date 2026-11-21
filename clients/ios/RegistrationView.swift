import SwiftUI
#if canImport(UIKit)
import UIKit
#endif

/// Sign in or create an account.
struct RegistrationView: View {
    @ObservedObject var client: ShroudClient
    @State private var creating = false
    @State private var username = ""
    @State private var password = ""
    @State private var confirm = ""
    @State private var deviceName = RegistrationView.defaultDeviceName
    @State private var relayURL = Relay.shared.baseURL
    @State private var busy = false
    @State private var error: String?

    static var defaultDeviceName: String {
        #if canImport(UIKit)
        return UIDevice.current.name
        #else
        return Host.current().localizedName ?? "Mac"
        #endif
    }

    private var problem: String? {
        if username.trimmingCharacters(in: .whitespaces).count < 3 { return "Usernames are at least 3 characters." }
        if creating && password.count < 12 { return "Use a password of at least 12 characters." }
        if creating && password != confirm { return "The passwords don't match." }
        if !creating && password.isEmpty { return "Enter your password." }
        return nil
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("SHROUD", systemImage: "lock.shield.fill").font(.title2.bold())
                        Text("Messages are encrypted on this device. The relay only ever sees sealed, " +
                             "padded envelopes, never who you are talking to or what you say.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                    Picker("", selection: $creating) {
                        Text("Sign in").tag(false)
                        Text("Create account").tag(true)
                    }
                    .pickerStyle(.segmented)
                }

                Section("Account") {
                    TextField("Username", text: $username)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        #endif
                    SecureField(creating ? "Password (12+ characters)" : "Password", text: $password)
                        #if os(iOS)
                        .textContentType(creating ? UITextContentType.newPassword : UITextContentType.password)
                        #endif
                    if creating {
                        SecureField("Confirm password", text: $confirm)
                        Text("There is no password reset. The relay can't recover your account, by design.")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }

                Section("This device") {
                    TextField("Device name", text: $deviceName)
                }

                Section {
                    TextField("Relay address", text: $relayURL)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        #endif
                } header: { Text("Relay") } footer: {
                    Text("Leave this alone unless you run your own relay. Accounts belong to one relay.")
                }

                if let e = error {
                    Section { Text(e).foregroundStyle(.red) }
                }

                Section {
                    Button(action: submit) {
                        HStack {
                            Spacer()
                            if busy { ProgressView() } else {
                                Text(creating ? "Create account" : "Sign in").bold()
                            }
                            Spacer()
                        }
                    }
                    .disabled(problem != nil || busy)
                    if let p = problem, !username.isEmpty || !password.isEmpty {
                        Text(p).font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle(creating ? "Create account" : "Sign in")
        }
    }

    private func submit() {
        busy = true
        error = nil
        let url = relayURL.trimmingCharacters(in: .whitespaces)
        if !url.isEmpty, url != Relay.shared.baseURL { Relay.shared.baseURL = url }
        Task {
            do {
                try await client.auth(username: username, password: password,
                                      deviceName: deviceName, register: creating)
            } catch {
                self.error = Relay.describe(error)
            }
            busy = false
        }
    }
}
