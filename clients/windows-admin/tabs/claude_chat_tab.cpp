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

ClaudeChatTab::ClaudeChatTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    m_status = new QLabel("Idle. Set Anthropic API key in Settings if not configured.");
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

void ClaudeChatTab::onSend() {
    QString text = m_input->toPlainText().trimmed();
    if (text.isEmpty()) return;
    m_input->clear();
    m_status->setText("Sending…");
    m_sendBtn->setEnabled(false);

    QJsonObject userMsg;
    userMsg["role"]    = "user";
    userMsg["content"] = text;
    m_messages.append(userMsg);

    m_history->append("<div style='color:#7fbfff;margin:8px 0 4px 0'><b>You</b></div>");
    m_history->append("<div style='margin-left:8px'>" + escapeHtml(text) + "</div>");

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
            m_history->append("<div style='color:#ffb74d;margin:8px 0 4px 0'><b>Claude</b></div>");
            m_history->append("<div style='margin-left:8px;white-space:pre-wrap'>"
                              + escapeHtml(reply) + "</div>");
            m_status->setText("Idle.");
            auto bar = m_history->verticalScrollBar();
            if (bar) bar->setValue(bar->maximum());
        });
}
