#include "settings_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QSettings>
#include <QDir>
#include <QJsonArray>
#include <QJsonObject>

SettingsTab::SettingsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Sensitive values (Anthropic key, admin session cookie) are stored "
        "via <code>QSettings</code> in <code>HKCU\\Software\\SHROUD\\admin</code>. "
        "This is plaintext on disk; protect your Windows user account.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *fl = new QFormLayout;
    QSettings s("SHROUD", "admin");
    m_relayUrl      = new QLineEdit(m_client->relayUrl());
    m_sessionCookie = new QLineEdit(m_client->adminSessionCookie());
    m_sessionCookie->setEchoMode(QLineEdit::Password);
    m_anthropicKey  = new QLineEdit(m_client->anthropicKey());
    m_anthropicKey->setEchoMode(QLineEdit::Password);
    m_socksProxy    = new QLineEdit(m_client->socksProxy());
    m_socksProxy->setPlaceholderText("127.0.0.1:9050 (Tor) — leave empty for direct");
    m_diagKeyfile     = new QLineEdit(s.value("diag_keyfile",
        QDir::home().filePath(".config/shroud/diag.keypair.json")).toString());
    m_manifestKeyfile = new QLineEdit(s.value("manifest_keyfile",
        QDir::home().filePath(".config/shroud/manifest.ed25519.json")).toString());

    fl->addRow("Relay URL",              m_relayUrl);
    fl->addRow("SOCKS5 proxy (Tor)",     m_socksProxy);
    fl->addRow("Admin session cookie",   m_sessionCookie);
    fl->addRow("Anthropic API key",      m_anthropicKey);
    fl->addRow("Diagnostics keyfile",    m_diagKeyfile);
    fl->addRow("Manifest signing keyfile", m_manifestKeyfile);
    l->addLayout(fl);

    // Login group — alternative to pasting a cookie
    auto *loginBar = new QHBoxLayout;
    m_loginUser = new QLineEdit;  m_loginUser->setPlaceholderText("Admin username");
    m_loginPass = new QLineEdit;  m_loginPass->setPlaceholderText("Password");
    m_loginPass->setEchoMode(QLineEdit::Password);
    m_loginBtn  = new QPushButton("Log in");
    m_loginBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    m_logoutBtn = new QPushButton("Log out");
    loginBar->addWidget(new QLabel("Login →"));
    loginBar->addWidget(m_loginUser, 1);
    loginBar->addWidget(m_loginPass, 1);
    loginBar->addWidget(m_loginBtn);
    loginBar->addWidget(m_logoutBtn);
    l->addLayout(loginBar);

    auto *bar = new QHBoxLayout;
    m_saveBtn = new QPushButton("Save");
    m_saveBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    m_testRelayBtn = new QPushButton("Test relay");
    m_testAnthropicBtn = new QPushButton("Test Anthropic key");
    bar->addWidget(m_saveBtn);
    bar->addStretch();
    bar->addWidget(m_testRelayBtn);
    bar->addWidget(m_testAnthropicBtn);
    l->addLayout(bar);

    m_status = new QLabel;
    m_status->setStyleSheet("padding:6px;color:#aaa");
    m_status->setWordWrap(true);
    l->addWidget(m_status);
    l->addStretch();

    connect(m_saveBtn, &QPushButton::clicked, this, &SettingsTab::onSave);
    connect(m_testRelayBtn, &QPushButton::clicked, this, &SettingsTab::onTestRelay);
    connect(m_testAnthropicBtn, &QPushButton::clicked, this, &SettingsTab::onTestAnthropic);
    connect(m_loginBtn,  &QPushButton::clicked, [this]() {
        m_status->setText("Logging in…");
        m_loginBtn->setEnabled(false);
        m_client->adminLogin(m_loginUser->text().trimmed(), m_loginPass->text(),
            [this](bool ok, const QString &err) {
                m_loginBtn->setEnabled(true);
                if (ok) {
                    m_status->setText("Logged in. Session captured.");
                    m_sessionCookie->setText(m_client->adminSessionCookie());
                    m_loginPass->clear();
                } else {
                    m_status->setText("Login failed: " + err);
                }
            });
    });
    connect(m_logoutBtn, &QPushButton::clicked, [this]() {
        m_client->adminLogout([this](bool ok) {
            m_status->setText(ok ? "Logged out." : "Logout request failed (cookie cleared locally).");
            m_sessionCookie->clear();
        });
    });
}

void SettingsTab::onSave() {
    m_client->setRelayUrl(m_relayUrl->text().trimmed());
    m_client->setAdminSessionCookie(m_sessionCookie->text().trimmed());
    m_client->setAnthropicKey(m_anthropicKey->text().trimmed());
    m_client->setSocksProxy(m_socksProxy->text().trimmed());
    QSettings s("SHROUD", "admin");
    s.setValue("diag_keyfile",     m_diagKeyfile->text());
    s.setValue("manifest_keyfile", m_manifestKeyfile->text());
    m_status->setText("Saved.");
    emit relayUrlChanged(m_relayUrl->text().trimmed());
}

void SettingsTab::onTestRelay() {
    m_status->setText("Testing relay…");
    m_client->getJson("/health",
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) m_status->setText("Relay test FAILED: " + err);
            else                m_status->setText("Relay test OK: " +
                QString::fromUtf8(d.toJson(QJsonDocument::Compact)));
        });
}

void SettingsTab::onTestAnthropic() {
    m_status->setText("Testing Anthropic key…");
    QJsonArray msgs;
    QJsonObject m; m["role"] = "user"; m["content"] = "say 'pong' and nothing else";
    msgs.append(m);
    m_client->anthropicMessage(msgs, "", 16,
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) { m_status->setText("Anthropic FAILED: " + err); return; }
            auto o = d.object();
            if (o.contains("error")) {
                m_status->setText("Anthropic FAILED: " + QString::fromUtf8(d.toJson(QJsonDocument::Compact)));
            } else {
                m_status->setText("Anthropic OK.");
            }
        });
}
