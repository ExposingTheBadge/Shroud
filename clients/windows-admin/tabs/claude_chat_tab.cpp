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

    m_systemPrompt =
        "You are an embedded operator assistant inside the SHROUD admin "
        "client. The operator runs a federated post-quantum messenger "
        "(SHROUD) across multiple AWS regions. Help with: release notes, "
        "debugging server errors, summarizing federation health JSON, "
        "explaining anon-routing and operator-manifest workflows, "
        "drafting incident reports, and writing short PowerShell / bash "
        "/ SQL snippets. Be concise. Output Markdown.";
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
