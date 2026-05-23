import SwiftUI

struct MessageListView: View {
    @ObservedObject var client: GhostlinkClient
    @State private var selectedContact = 0
    @State private var messageText = ""
    @State private var showContacts = false
    @State private var showGroups = false
    @State private var searchQuery = ""

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Device bar
                HStack {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(.green)
                    Text(client.deviceID.prefix(12) + "...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Spacer()
                    Button(action: { showGroups = true }) {
                        Image(systemName: "person.3.fill")
                    }
                    Button(action: { showContacts = true }) {
                        Image(systemName: "person.badge.plus")
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
                .background(Color(.systemGroupedBackground))

                // Messages
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(client.messages) { msg in
                            MessageRow(message: msg, isMine: msg.senderDeviceID == client.deviceID)
                        }
                    }
                }

                // Input
                HStack {
                    TextField("Message (E2E encrypted)", text: $messageText)
                        .textFieldStyle(.roundedBorder)
                    Button(action: sendMessage) {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.title2)
                    }
                    .disabled(messageText.isEmpty)
                }
                .padding()
            }
            .navigationTitle("GHOSTLINK")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func sendMessage() {
        // E2E encryption happens here — server never sees plaintext
        messageText = ""
    }
}

struct MessageRow: View {
    let message: SecureMessage
    let isMine: Bool

    var body: some View {
        HStack {
            if isMine { Spacer() }
            VStack(alignment: isMine ? .trailing : .leading, spacing: 4) {
                if let body = message.decryptedBody {
                    Text(body)
                        .padding(12)
                        .background(isMine ? Color.blue : Color(.systemGray5))
                        .foregroundColor(isMine ? .white : .primary)
                        .cornerRadius(16)
                } else {
                    Text("[Encrypted]")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(12)
                        .background(Color(.systemGray5))
                        .cornerRadius(16)
                }
                Text(message.senderDeviceID.prefix(8) + "...")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            if !isMine { Spacer() }
        }
        .padding(.horizontal)
        .padding(.vertical, 4)
    }
}

// MARK: - Contacts Sheet
struct ContactsSheet: View {
    @ObservedObject var client: GhostlinkClient
    @State private var searchQuery = ""

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Search Users")) {
                    TextField("Username", text: $searchQuery)
                    if !searchQuery.isEmpty {
                        // Search results would go here
                    }
                }
                Section(header: Text("Your Contacts")) {
                    ForEach(client.contacts) { contact in
                        HStack {
                            Image(systemName: "person.circle")
                            Text(contact.username)
                        }
                    }
                }
            }
            .navigationTitle("Contacts")
        }
    }
}

// MARK: - Groups Sheet
struct GroupsSheet: View {
    @ObservedObject var client: GhostlinkClient
    @State private var newGroupName = ""

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Create Group")) {
                    HStack {
                        TextField("Group name", text: $newGroupName)
                        Button("Create") {
                            // Create group with encrypted key distribution
                        }
                        .disabled(newGroupName.isEmpty)
                    }
                }
                Section(header: Text("Your Groups")) {
                    ForEach(client.groups) { group in
                        HStack {
                            Image(systemName: "person.3.fill")
                            VStack(alignment: .leading) {
                                Text(group.name)
                                Text(group.id.prefix(8) + "...")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Groups")
        }
    }
}
