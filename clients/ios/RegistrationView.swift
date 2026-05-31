import SwiftUI

struct RegistrationView: View {
    @ObservedObject var client: ShroudClient
    @State private var username = ""
    @State private var password = ""
    @State private var deviceName = UIDevice.current.name
    @State private var isRegistering = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Account")) {
                    TextField("Username", text: $username)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    SecureField("Password (12+ chars)", text: $password)
                }

                Section(header: Text("Device")) {
                    TextField("Device Name", text: $deviceName)
                    Text("Platform: iOS \(UIDevice.current.systemVersion)")
                        .foregroundColor(.secondary)
                }

                if let error = errorMessage {
                    Section {
                        Text(error).foregroundColor(.red)
                    }
                }

                Section {
                    Button(action: register) {
                        if isRegistering {
                            ProgressView()
                        } else {
                            Text("Register Device")
                                .frame(maxWidth: .infinity)
                                .fontWeight(.bold)
                        }
                    }
                    .disabled(username.count < 3 || password.count < 12 || isRegistering)
                }
            }
            .navigationTitle("SHROUD Setup")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func register() {
        isRegistering = true; errorMessage = nil
        Task {
            do {
                try await client.register(
                    username: username,
                    password: password,
                    deviceName: deviceName,
                    platform: "ios"
                )
            } catch {
                await MainActor.run {
                    errorMessage = error.localizedDescription
                    isRegistering = false
                }
            }
        }
    }
}
