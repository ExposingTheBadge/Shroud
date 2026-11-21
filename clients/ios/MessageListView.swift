import SwiftUI

// MARK: - Conversation list

struct ConversationsView: View {
    @ObservedObject var client: ShroudClient
    @State private var showAdd = false
    @State private var showSettings = false

    /// Contacts plus anyone who has written to us, most recent first.
    private var peers: [String] {
        let all = Set(client.contacts).union(client.conversations.keys)
        return all.sorted { a, b in
            let ta = client.conversations[a]?.last?.ts ?? .distantPast
            let tb = client.conversations[b]?.last?.ts ?? .distantPast
            return ta == tb ? a < b : ta > tb
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 8) {
                        Circle().fill(client.connected ? Color.green : Color.orange).frame(width: 8, height: 8)
                        Text(client.connection).font(.footnote).foregroundStyle(.secondary)
                    }
                }

                if !client.incomingRequests.isEmpty {
                    Section("Contact requests") {
                        ForEach(client.incomingRequests) { req in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(req.from).bold()
                                if !req.reason.isEmpty { Text(req.reason).font(.callout).foregroundStyle(.secondary) }
                                HStack {
                                    Button("Accept") { Task { await client.respond(req, accept: true) } }
                                        .buttonStyle(.borderedProminent)
                                    Button("Decline", role: .destructive) { Task { await client.respond(req, accept: false) } }
                                        .buttonStyle(.bordered)
                                }
                            }
                            .padding(.vertical, 4)
                        }
                    }
                }

                Section("Conversations") {
                    if peers.isEmpty {
                        Text("No contacts yet. Tap + and enter a friend's username to send them a request.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(peers, id: \.self) { peer in
                        NavigationLink(value: peer) { ConversationRow(client: client, peer: peer) }
                            .swipeActions {
                                if client.conversations[peer] != nil {
                                    Button("Clear", role: .destructive) { client.deleteConversation(peer) }
                                }
                            }
                    }
                }

                if !client.outgoingPending.isEmpty {
                    Section("Waiting for them to accept") {
                        ForEach(client.outgoingPending, id: \.self) { Text($0).foregroundStyle(.secondary) }
                    }
                }
            }
            .navigationTitle("SHROUD")
            .navigationDestination(for: String.self) { ChatView(client: client, peer: $0) }
            .refreshable { await client.refreshContacts() }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showAdd = true } label: { Image(systemName: "plus") }
                        .accessibilityLabel("Add contact")
                }
                ToolbarItem(placement: .navigation) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                        .accessibilityLabel("Settings")
                }
            }
            .sheet(isPresented: $showAdd) { AddContactSheet(client: client) }
            .sheet(isPresented: $showSettings) { SettingsSheet(client: client) }
            .alert("Notice", isPresented: Binding(get: { client.notice != nil }, set: { if !$0 { client.notice = nil } })) {
                Button("OK", role: .cancel) {}
            } message: { Text(client.notice ?? "") }
        }
    }
}

private struct ConversationRow: View {
    @ObservedObject var client: ShroudClient
    let peer: String

    var body: some View {
        HStack(spacing: 12) {
            Avatar(name: peer)
            VStack(alignment: .leading, spacing: 2) {
                Text(peer).font(.headline)
                Text(client.conversations[peer]?.last?.body ?? "Say hello")
                    .font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if let n = client.unread[peer], n > 0 {
                Text("\(n)").font(.caption.bold()).padding(.horizontal, 7).padding(.vertical, 2)
                    .background(Capsule().fill(Color.accentColor)).foregroundColor(.white)
            }
        }
    }
}

struct Avatar: View {
    let name: String
    var body: some View {
        // Stable across launches, unlike hashValue.
        let hue = Double(name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) % 360 }) / 360
        Circle().fill(Color(hue: hue, saturation: 0.45, brightness: 0.75))
            .frame(width: 40, height: 40)
            .overlay(Text(String(name.prefix(1)).uppercased()).font(.headline).foregroundColor(.white))
    }
}

// MARK: - Chat

struct ChatView: View {
    @ObservedObject var client: ShroudClient
    let peer: String
    @State private var draft = ""
    @State private var safety: String?
    @State private var showSafety = false

    private var messages: [ChatMessage] { client.conversations[peer] ?? [] }

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(messages) { m in
                            Bubble(message: m) { client.retry(m, to: peer) }.id(m.id)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.vertical, 8)
                }
                .onAppear { if let l = messages.last { proxy.scrollTo(l.id, anchor: .bottom) } }
                .onChange(of: messages.count) { _ in
                    if let l = messages.last { withAnimation { proxy.scrollTo(l.id, anchor: .bottom) } }
                }
            }
            Divider()
            HStack(alignment: .bottom, spacing: 8) {
                TextField("Message", text: $draft, axis: .vertical)
                    .lineLimit(1...5)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(send)
                Button(action: send) { Image(systemName: "arrow.up.circle.fill").font(.title) }
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || client.maintenance)
                    .accessibilityLabel("Send")
            }
            .padding(10)
        }
        .navigationTitle(peer)
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .onAppear { client.open(peer) }
        .onDisappear { if client.openPeer == peer { client.openPeer = nil } }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    Task { safety = await client.safetyNumber(for: peer); showSafety = true }
                } label: { Image(systemName: "checkmark.shield") }
                .accessibilityLabel("Safety number")
            }
        }
        .alert("Safety number", isPresented: $showSafety) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(safety.map { "Compare this with \(peer), in person or on a call. If it matches on both " +
                              "phones, nobody is in the middle.\n\n\($0)" }
                 ?? "\(peer) hasn't published encryption keys yet, so there's nothing to compare.")
        }
    }

    private func send() {
        client.send(draft, to: peer)
        draft = ""
    }
}

private struct Bubble: View {
    let message: ChatMessage
    let onRetry: () -> Void

    var body: some View {
        if message.system {
            Text(message.body).font(.footnote).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity).padding(.vertical, 4)
        } else {
            HStack {
                if message.outgoing { Spacer(minLength: 40) }
                VStack(alignment: message.outgoing ? .trailing : .leading, spacing: 3) {
                    Text(message.body)
                        .textSelection(.enabled)
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .background(RoundedRectangle(cornerRadius: 16)
                            .fill(message.outgoing ? Color.accentColor : Color.gray.opacity(0.2)))
                        .foregroundColor(message.outgoing ? .white : .primary)
                    HStack(spacing: 4) {
                        Text(message.ts, style: .time)
                        if message.pending { Text("· sending") }
                        if let f = message.failed {
                            Text("· not sent: \(f)").foregroundColor(.red)
                            Button("Retry", action: onRetry).font(.caption2.bold())
                        }
                    }
                    .font(.caption2).foregroundStyle(.secondary)
                }
                if !message.outgoing { Spacer(minLength: 40) }
            }
        }
    }
}

// MARK: - Sheets

struct AddContactSheet: View {
    @ObservedObject var client: ShroudClient
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Their username", text: $name)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } footer: {
                    Text("They'll get a request. You can message each other once they accept. " +
                         "The relay only finds exact usernames, so nobody can browse its users.")
                }
                if let e = error { Section { Text(e).foregroundStyle(.red) } }
            }
            .navigationTitle("Add contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(busy ? "Sending…" : "Send request") {
                        busy = true
                        Task {
                            error = await client.addContact(name)
                            busy = false
                            if error == nil { dismiss() }
                        }
                    }
                    .disabled(name.trimmingCharacters(in: .whitespaces).count < 3 || busy)
                }
            }
        }
    }
}

struct SettingsSheet: View {
    @ObservedObject var client: ShroudClient
    @Environment(\.dismiss) private var dismiss
    @State private var confirmSignOut = false

    private let timers: [(String, Int)] = [("Off", 0), ("5 minutes", 300), ("1 hour", 3600),
                                           ("1 day", 86_400), ("1 week", 604_800)]

    var body: some View {
        NavigationStack {
            Form {
                Section("Account") {
                    LabeledContent("Username", value: client.username)
                    LabeledContent("Relay", value: Relay.shared.baseURL)
                }
                Section {
                    Picker("Disappearing messages", selection: $client.disappearSeconds) {
                        ForEach(timers.indices, id: \.self) { i in Text(timers[i].0).tag(timers[i].1) }
                    }
                } footer: {
                    Text("New messages you send are deleted from the relay after this time, even if they were never collected.")
                }
                Section {
                    Toggle("Anonymous routing", isOn: $client.useAnonRouting)
                } footer: {
                    Text("Sends sealed envelopes to rotating routing tags, so the relay can't see who is " +
                         "writing to whom. Leave this on.")
                }
                Section {
                    Button("Sign out", role: .destructive) { confirmSignOut = true }
                } footer: {
                    Text("Signing out deletes this device's keys and message history.")
                }
            }
            .navigationTitle("Settings")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog("Sign out and delete this device's keys and messages?",
                                isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button("Sign out", role: .destructive) { client.signOut(); dismiss() }
            }
        }
    }
}
