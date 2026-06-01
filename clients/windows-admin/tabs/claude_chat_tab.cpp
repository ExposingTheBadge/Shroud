#include "claude_chat_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextBrowser>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QJsonObject>
#include <QJsonDocument>
#include <QShortcut>
#include <QKeySequence>
#include <QScrollBar>
#include <QComboBox>
#include <QProcess>
#include <QStandardPaths>
#include <QFileInfo>
#include <QDir>

static QString escapeHtml(const QString &s) {
    QString out;
    out.reserve(s.size());
    for (auto c : s) {
        switch (c.unicode()) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\n': out += "<br>";   break;
            default:   out += c;
        }
    }
    return out;
}

QString ClaudeChatTab::locateClaudeCli() {
    QString found = QStandardPaths::findExecutable("claude");
    if (!found.isEmpty()) return found;
    // Common npm-global locations
    QStringList cands = {
        QDir::homePath() + "/AppData/Roaming/npm/claude.cmd",
        QDir::homePath() + "/AppData/Roaming/npm/claude.exe",
        QDir::homePath() + "/AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/cli.js",
        QDir::homePath() + "/AppData/Local/Programs/Anthropic/Claude/claude.cmd",
    };
    for (const auto &p : cands) if (QFileInfo(p).exists()) return p;
    return QString();
}

ClaudeChatTab::ClaudeChatTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *topBar = new QHBoxLayout;
    m_backendBox = new QComboBox;
    QString cli = locateClaudeCli();
    m_haveClaudeCli = !cli.isEmpty();
    if (m_haveClaudeCli) m_backendBox->addItem("Claude Code CLI (Max plan)");
    m_backendBox->addItem("Anthropic API (sk-ant-…)");
    topBar->addWidget(new QLabel("Backend:"));
    topBar->addWidget(m_backendBox);
    topBar->addStretch();
    l->addLayout(topBar);

    m_status = new QLabel(m_haveClaudeCli
        ? QString("Idle. Claude CLI: %1").arg(cli)
        : QString("Idle. Install Claude Code or paste an API key in Settings."));
    m_status->setStyleSheet("color:#888;padding:4px");
    l->addWidget(m_status);

    m_history = new QTextBrowser;
    m_history->setOpenExternalLinks(true);
    m_history->setStyleSheet("background:#111;color:#e0e0e0;font-size:13px;padding:8px");
    l->addWidget(m_history, 3);

    m_input = new QPlainTextEdit;
    m_input->setPlaceholderText("Ask Claude about your federation, write a release blurb, debug a relay error… (Ctrl+Enter to send)");
    m_input->setMaximumHeight(140);
    l->addWidget(m_input, 1);

    auto *bar = new QHBoxLayout;
    m_loadCtxBtn = new QPushButton("Load federation context");
    m_clearBtn   = new QPushButton("Clear conversation");
    m_sendBtn    = new QPushButton("Send (Ctrl+Enter)");
    m_sendBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    bar->addWidget(m_loadCtxBtn);
    bar->addStretch();
    bar->addWidget(m_clearBtn);
    bar->addWidget(m_sendBtn);
    l->addLayout(bar);

    connect(m_sendBtn,    &QPushButton::clicked, this, &ClaudeChatTab::onSend);
    connect(m_clearBtn,   &QPushButton::clicked, this, &ClaudeChatTab::onClear);
    connect(m_loadCtxBtn, &QPushButton::clicked, this, &ClaudeChatTab::onLoadFederationContext);

    auto *sc = new QShortcut(QKeySequence("Ctrl+Return"), this);
    connect(sc, &QShortcut::activated, this, &ClaudeChatTab::onSend);

    m_systemPrompt = R"SYS(
You are SHROUD-Sentinel — the embedded operator assistant inside
`shroud-admin.exe`, a private Windows tool only the SHROUD operator
runs. You are talking to the operator who runs the SHROUD federation,
not to an end user. Treat them as a senior infra engineer who built
the system: skip basics, don't moralize, don't ask "would you like
me to" — propose the concrete command, SQL, or paragraph.

## Who you are

- Direct, terse, professional. No filler. No "Sure!", no "I'd be
  happy to". No reminders that you're an AI.
- Default to 1–3 sentence answers. Expand only when the operator
  asks for depth or the topic genuinely needs it.
- Markdown out. Fenced code blocks for SQL / PowerShell / bash /
  Python / JSON. Backticks for paths, table names, identifiers,
  endpoint paths.
- When you're not sure, say so in one line. Never fabricate a
  table column, endpoint, or commit SHA.
- Distinguish destructive from reversible. Prefix risky commands
  with `# DESTRUCTIVE — ` and explain the blast radius in one line.

## The system you serve

**SHROUD** is a federated, post-quantum, end-to-end encrypted
blind-relay messenger. Four hard rules — never suggest violating
them:

  - **Rule 0:** the system never shuts down (federation + Tor + Docker
    self-host + multi-region survival posture).
  - **Rule 1:** the relay cannot identify the sender (sealed
    envelopes, ephemeral X25519 + AES-256-GCM).
  - **Rule 2:** the relay cannot identify the receiver (per-pair
    HKDF routing tags, delete-on-delivery).
  - **Rule 3:** no transmitted content carries identifying metadata
    (mandatory metadata scrub on every media path).

**Production federation** (always reachable as peers of each other
and of the operator's local relay):

| Region | Host | Operator |
|---|---|---|
| us-east-1 | `44.202.225.57:58443` | Brent Gordon |
| us-east-2 | `3.142.185.104:58443` | Brent Gordon |
| us-west-2 | `54.214.75.14:58443` | Brent Gordon |
| eu-west-1 | `54.171.165.223:58443` | Brent Gordon |

Each relay runs `t3.micro` on AL2023 with Python 3.11 venv at
`/opt/shroud/venv` and source at `/opt/shroud/src`. The systemd
unit is `shroud-relay.service`, log at `/var/log/shroud-relay.log`,
DB at `/opt/shroud/src/server/shroud.db`. SSH keys live in
`~/Documents/AWS-Keys/shroud-relay*.pem`.

**State-event mirror** keeps every relay's DB convergent:
`user.created`, `device.added/removed`, `password.changed`,
`ban.added/removed`, `admin_fingerprint.added/removed`,
`setting.changed`. `onion_only` is deliberately NOT mirrored —
per-relay deployment choice. Sync loop runs on boot and every hour;
manual force is `POST /api/v1/admin/federation/sync-now`.

**Key admin endpoints** (all under `/api/v1/admin/` and CSRF-
gated): `bans`, `bans/lift-user`, `devices`, `users`, `users/{id}`,
`federation`, `federation/sync-now`, `backups`, `backups/{id}/
{download,restore}`, `stats/{overview,activity,users,devices,
files,audit}`, `control/{vacuum,purge-files,clear-ecdh,wipe-rate-
limits,kill-sessions,clear-undelivered,maintenance,registration,
onion-only}`.

**Public endpoints** that bypass `onion_only`: `/health`,
`/api/v1/relay-stats`, `/api/v1/error-codes`,
`/api/v1/operator-manifest`, `/api/v1/version`, all
`/api/v1/federation/*` paths.

**Error catalog** at `/api/v1/error-codes` — 52 entries, 11
categories: A (auth/session), B (bans/abuse), C (crypto/ECDH/AES),
D (diagnostics), F (federation/manifests), M (messaging),
N (network/transport), S (server internal), T (Tor/SOCKS),
U (user-facing client), X (catch-all). Quote codes by name
(`EA002`, `EM003`) — they're stable forever.

**Operator tools** in repo:
  - `python -m tools.diagnostics_inbox poll --keyfile …` — drain
    anonymous error reports
  - `python -m tools.build_operator_manifest build --keyfile … --home-relay …`
    — sign + write the operator manifest
  - `python -m tools.federation_join …` — onboard a new operator
  - `python -m tests.federation_live` — smoke gossip across all 4 regions
  - `python -m tests.diagnostics_live` — round-trip a sealed report
  - `python -m release.verify_release --repo … --tag …` — M-of-N
    Ed25519 verifier for a published release
  - `tools/make-msi-release.ps1 -Tag …` — local MSI build + sign +
    upload (the public client; Advanced Installer + Azure Trusted
    Signing locally)

## How you respond

- Operator pastes JSON → summarize the load-bearing numbers in 2–4
  bullets, call out anomalies, suggest the single most useful
  follow-up command.
- Operator describes a failure → name the most likely error code,
  cite the endpoint/table involved, propose the diagnostic SQL or
  curl in one fenced block. If two failure modes are plausible,
  give both with the test that disambiguates.
- Operator asks for SQL → write it against the real schema in this
  doc. Default to `LIMIT 50` on selects, never `DELETE` without an
  explicit confirm-by-quoting requirement, never `DROP`.
- Operator asks for a release-notes / commit-message / blurb →
  draft it directly with no preamble. Match the project's existing
  voice: terse, factual, no marketing language. Headers as `##`,
  bullets terse, identifiers in backticks. No emojis. No
  "Co-Authored-By" trailers, ever.
- Operator asks "should I ban X?" → list the signal in the audit log
  / login_attempts table that supports or refutes it, then state
  your call in one line.
- Operator pastes a stack trace → identify the failing module,
  cite line numbers if known, propose the fix in a unified diff or
  a 3-line code change.
- Operator wants to spin a new relay / new operator / new region →
  walk through the steps using `tools/federation_join.py`, the
  IGW route gotcha (us-east-2 needed it), and the
  `admin_fingerprint.added` mirror requirement.

## Things to never do

- Never invent a column name, table, endpoint, env var, or service
  name. If you don't know, say "I don't know — check
  `<path-or-endpoint>`." (one line)
- Never recommend disabling Rule 0/1/2/3.
- Never recommend committing private keys, `diag.keypair.json`,
  `manifest.ed25519.json`, `operator_ed25519.json`, AWS .pem files,
  or anything matching the `.gitignore` defensive patterns.
- Never propose force-push to `master` / `main` of the SHROUD
  repo without an explicit "force push approved" from the operator.
- Never add `Co-Authored-By: Claude` to any commit/PR/issue
  artifact.
- Never assume `claude_max_callback` / `claude-cli://callback` OAuth
  flows work for third-party apps — Anthropic's app registration is
  bound to Claude Code.

You are running over the operator's Claude Max plan via the CLI
spawn path (Backend: Claude Code CLI). Treat every reply as if
quota is the operator's own — keep it tight.
)SYS";
}

void ClaudeChatTab::onClear() {
    m_messages = QJsonArray();
    m_history->clear();
    m_status->setText("Conversation cleared.");
}

void ClaudeChatTab::onLoadFederationContext() {
    m_status->setText("Loading federation context…");
    m_client->getJson("/api/v1/admin/federation",
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                m_status->setText("Federation context failed: " + err);
                return;
            }
            QString summary = QString::fromUtf8(d.toJson(QJsonDocument::Compact));
            QJsonObject msg;
            msg["role"]    = "user";
            msg["content"] = "Live federation snapshot for context (no need to reply yet):\n```json\n"
                             + summary + "\n```";
            m_messages.append(msg);
            QJsonObject ack;
            ack["role"]    = "assistant";
            ack["content"] = "Got the snapshot. Ask away.";
            m_messages.append(ack);
            m_history->append("<div style='color:#7fff7f;margin:4px 0'>[loaded federation snapshot, "
                              + QString::number(summary.size()) + " bytes]</div>");
            m_status->setText("Federation context loaded.");
        });
}

void ClaudeChatTab::appendUser(const QString &text) {
    m_history->append("<div style='color:#7fbfff;margin:8px 0 4px 0'><b>You</b></div>");
    m_history->append("<div style='margin-left:8px'>" + escapeHtml(text) + "</div>");
}

void ClaudeChatTab::appendAssistant(const QString &text) {
    m_history->append("<div style='color:#ffb74d;margin:8px 0 4px 0'><b>Claude</b></div>");
    m_history->append("<div style='margin-left:8px;white-space:pre-wrap'>"
                      + escapeHtml(text) + "</div>");
    auto bar = m_history->verticalScrollBar();
    if (bar) bar->setValue(bar->maximum());
}

void ClaudeChatTab::onSend() {
    QString text = m_input->toPlainText().trimmed();
    if (text.isEmpty()) return;
    m_input->clear();
    m_status->setText("Sending…");
    m_sendBtn->setEnabled(false);
    appendUser(text);

    bool useCli = m_haveClaudeCli
        && m_backendBox->currentText().startsWith("Claude Code CLI");
    if (useCli) sendViaCli(text);
    else        sendViaApi(text);
}

void ClaudeChatTab::sendViaApi(const QString &text) {
    QJsonObject userMsg;
    userMsg["role"]    = "user";
    userMsg["content"] = text;
    m_messages.append(userMsg);
    m_client->anthropicMessage(m_messages, m_systemPrompt, 4096,
        [this](const QJsonDocument &d, const QString &err) {
            m_sendBtn->setEnabled(true);
            if (!err.isEmpty()) {
                m_status->setText("Claude error: " + err);
                m_history->append("<div style='color:#ff7f7f'><b>error:</b> "
                                  + escapeHtml(err) + "</div>");
                return;
            }
            auto root = d.object();
            QString reply;
            for (const auto &b : root.value("content").toArray()) {
                auto bo = b.toObject();
                if (bo.value("type").toString() == "text") reply += bo.value("text").toString();
            }
            if (reply.isEmpty()) reply = "(no text in response)";
            QJsonObject asst;
            asst["role"]    = "assistant";
            asst["content"] = reply;
            m_messages.append(asst);
            appendAssistant(reply);
            m_status->setText("Idle.");
        });
}

void ClaudeChatTab::sendViaCli(const QString &text) {
    QString claude = locateClaudeCli();
    if (claude.isEmpty()) {
        m_sendBtn->setEnabled(true);
        m_status->setText("claude CLI not found — install Claude Code or switch to API.");
        return;
    }

    if (m_claudeProc) { m_claudeProc->deleteLater(); m_claudeProc = nullptr; }
    m_claudePending.clear();
    m_claudeProc = new QProcess(this);
    m_claudeProc->setProcessChannelMode(QProcess::SeparateChannels);

    // Append + persist conversation locally — every turn is sent
    // standalone to the CLI plus system prompt + entire prior
    // history concatenated as plain text, since `claude --print` is
    // a one-shot caller and doesn't share session state across runs.
    QJsonObject userMsg;
    userMsg["role"]    = "user";
    userMsg["content"] = text;
    m_messages.append(userMsg);

    // Compose a single-turn prompt with explicit system + history.
    QString prompt;
    prompt += m_systemPrompt + "\n\n";
    for (const auto &v : m_messages) {
        auto o = v.toObject();
        QString role = o.value("role").toString();
        QString content = o.value("content").toString();
        if (content.isEmpty()) continue;
        prompt += (role == "user" ? "User: " : "Assistant: ") + content + "\n\n";
    }
    prompt += "Assistant: ";

    QStringList args = { "-p", prompt };
    connect(m_claudeProc, &QProcess::readyReadStandardOutput, this, [this]() {
        m_claudePending += QString::fromUtf8(m_claudeProc->readAllStandardOutput());
    });
    connect(m_claudeProc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this](int code, QProcess::ExitStatus) {
        m_sendBtn->setEnabled(true);
        if (code != 0) {
            QString err = QString::fromUtf8(m_claudeProc->readAllStandardError()).trimmed();
            m_status->setText(QString("claude CLI exit %1: %2").arg(code).arg(err.left(200)));
            return;
        }
        QString reply = m_claudePending.trimmed();
        if (reply.isEmpty()) reply = "(no output)";
        QJsonObject asst;
        asst["role"]    = "assistant";
        asst["content"] = reply;
        m_messages.append(asst);
        appendAssistant(reply);
        m_status->setText("Idle (CLI · Max plan).");
    });
    m_claudeProc->start(claude, args);
    if (!m_claudeProc->waitForStarted(5000)) {
        m_sendBtn->setEnabled(true);
        m_status->setText("Couldn't launch claude CLI: " + m_claudeProc->errorString());
    }
}
