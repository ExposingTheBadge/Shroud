//
//  ShroudMacApp.swift
//  SHROUD macOS client — AppKit shell.
//
//  Imports the iOS AnonRouting.swift directly because CryptoKit is
//  identical on iOS 13+ and macOS 12+. Wraps the protocol layer in
//  a minimal AppKit UI: login + sidebar + chat + send box.
//

import AppKit
import Foundation

// Bring in the shared Swift crypto port. Build target should add
// clients/ios/AnonRouting.swift to its sources.

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var mainViewController: MainViewController!

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSApplication.shared.mainMenu ?? NSMenu()
        if NSApplication.shared.mainMenu == nil {
            NSApplication.shared.mainMenu = menu
            let appMenuItem = NSMenuItem()
            menu.addItem(appMenuItem)
            let appMenu = NSMenu()
            appMenuItem.submenu = appMenu
            appMenu.addItem(
                withTitle: "Quit SHROUD",
                action: #selector(NSApplication.terminate(_:)),
                keyEquivalent: "q"
            )
        }

        window = NSWindow(
            contentRect: NSRect(x: 100, y: 100, width: 900, height: 600),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "SHROUD"

        mainViewController = MainViewController()
        window.contentViewController = mainViewController
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}


// MARK: - Main view controller (sidebar + chat + send)

class MainViewController: NSViewController {
    private let sidebar = ContactSidebar()
    private let chat = ChatView()
    private let inputField = NSTextField()
    private let sendButton = NSButton(title: "Send", target: nil, action: nil)
    private let network = NetworkClient()
    private var selectedContact: Contact? = nil
    private var pollTimer: Timer?

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
        root.autoresizingMask = [.width, .height]

        // Sidebar
        sidebar.view.translatesAutoresizingMaskIntoConstraints = false
        sidebar.view.frame = NSRect(x: 0, y: 0, width: 220, height: 600)
        sidebar.didSelectContact = { [weak self] c in
            self?.selectedContact = c
            self?.chat.clear()
            self?.chat.append(line: "— chat with \(c.name) —")
        }
        addChild(sidebar)
        root.addSubview(sidebar.view)

        // Chat
        chat.view.translatesAutoresizingMaskIntoConstraints = false
        addChild(chat)
        root.addSubview(chat.view)

        // Input row
        let inputRow = NSStackView()
        inputRow.orientation = .horizontal
        inputRow.spacing = 6
        inputRow.translatesAutoresizingMaskIntoConstraints = false
        inputField.placeholderString = "Type a message and press Return"
        inputField.target = self
        inputField.action = #selector(send)
        inputField.setContentHuggingPriority(.defaultLow, for: .horizontal)
        sendButton.target = self
        sendButton.action = #selector(send)
        inputRow.addView(inputField, in: .leading)
        inputRow.addView(sendButton, in: .trailing)
        root.addSubview(inputRow)

        NSLayoutConstraint.activate([
            sidebar.view.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            sidebar.view.topAnchor.constraint(equalTo: root.topAnchor),
            sidebar.view.bottomAnchor.constraint(equalTo: root.bottomAnchor),
            sidebar.view.widthAnchor.constraint(equalToConstant: 220),

            chat.view.leadingAnchor.constraint(equalTo: sidebar.view.trailingAnchor),
            chat.view.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            chat.view.topAnchor.constraint(equalTo: root.topAnchor),
            chat.view.bottomAnchor.constraint(equalTo: inputRow.topAnchor, constant: -6),

            inputRow.leadingAnchor.constraint(equalTo: sidebar.view.trailingAnchor, constant: 8),
            inputRow.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -8),
            inputRow.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -8),
            inputRow.heightAnchor.constraint(equalToConstant: 30),
        ])

        view = root

        // Start polling
        pollTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.pollOnce()
        }
    }

    @objc private func send() {
        guard let contact = selectedContact else { return }
        let text = inputField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        Task {
            do {
                try await network.sendSealedAnon(to: contact, body: text)
                await MainActor.run {
                    self.chat.append(line: "me: \(text)")
                    self.inputField.stringValue = ""
                }
            } catch {
                await MainActor.run {
                    self.chat.append(line: "[send failed: \(error)]")
                }
            }
        }
    }

    private func pollOnce() {
        Task {
            do {
                let inbox = try await network.fetchAnonMessages(contacts: sidebar.contacts)
                await MainActor.run {
                    for m in inbox {
                        self.chat.append(line: "\(m.senderLabel): \(m.body)")
                    }
                }
            } catch {
                // ignore transient
            }
        }
    }
}


// MARK: - Sidebar

class ContactSidebar: NSViewController {
    var contacts: [Contact] = []
    var didSelectContact: ((Contact) -> Void)?
    private let tableView = NSTableView()

    override func loadView() {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.documentView = tableView
        scroll.translatesAutoresizingMaskIntoConstraints = false

        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("name"))
        col.title = "Contacts"
        col.width = 200
        tableView.addTableColumn(col)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.allowsMultipleSelection = false

        let v = NSView()
        v.addSubview(scroll)
        scroll.frame = v.bounds
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: v.topAnchor),
            scroll.leadingAnchor.constraint(equalTo: v.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: v.trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: v.bottomAnchor),
        ])
        view = v
    }

    func loadContacts() {
        // Placeholder — real loader reads ~/Library/Application Support/SHROUD/contacts.json
        contacts = []
        tableView.reloadData()
    }
}

extension ContactSidebar: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int { contacts.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let txt = NSTextField(labelWithString: contacts[row].name)
        return txt
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        let row = tableView.selectedRow
        if row >= 0 && row < contacts.count {
            didSelectContact?(contacts[row])
        }
    }
}


// MARK: - Chat view

class ChatView: NSViewController {
    private let textView = NSTextView()
    private let scroll = NSScrollView()

    override func loadView() {
        textView.isEditable = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        textView.textContainerInset = NSSize(width: 8, height: 8)

        scroll.hasVerticalScroller = true
        scroll.documentView = textView
        scroll.translatesAutoresizingMaskIntoConstraints = false

        view = scroll
    }

    func append(line: String) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedSystemFont(ofSize: 12, weight: .regular),
            .foregroundColor: NSColor.labelColor,
        ]
        let attr = NSAttributedString(string: line + "\n", attributes: attrs)
        textView.textStorage?.append(attr)
        textView.scrollToEndOfDocument(nil)
    }

    func clear() {
        textView.string = ""
    }
}


// MARK: - Models + Network

struct Contact {
    let name: String
    let identityPubkeyHex: String
    let sharedRootHex: String
}

struct ReceivedMessage {
    let senderLabel: String
    let body: String
}

class NetworkClient {
    var relayURL: URL = URL(string: "https://44.202.225.57:58443")!

    func sendSealedAnon(to contact: Contact, body: String) async throws {
        // Implementation calls into AnonRouting.swift + URLSession.
        // See AnonRouting.seal + URLRequest construction; mirrors
        // clients/python_sdk/shroud_client.py:send.
        // Left as exercise during macOS build wireup.
        _ = contact; _ = body
    }

    func fetchAnonMessages(contacts: [Contact]) async throws -> [ReceivedMessage] {
        // Mirror of clients/python_sdk/shroud_client.py:poll_once.
        return []
    }
}


// MARK: - Bootstrap

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
