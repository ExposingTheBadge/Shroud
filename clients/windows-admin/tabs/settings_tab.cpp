#include "settings_tab.h"
#include "../admin_client.h"
#include "../oauth_helper.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QSettings>
#include <QDir>
#include <QMessageBox>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QDateTime>
#include <QInputDialog>
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

    // Admin auth uses a 256-char hex fingerprint (minted at first-time
    // setup via /api/v1/admin/setup), not username/password. If the
    // relay has never been set up, "First-time setup" mints + returns
    // a fingerprint. Save it — it cannot be recovered.
    auto *authInfo = new QLabel(
        "<b>Admin auth:</b> 256-char hex fingerprint (minted by First-time setup) "
        "plus an optional password. First-time setup mints a fingerprint that "
        "<u>cannot be recovered</u> — save it somewhere safe.");
    authInfo->setWordWrap(true);
    authInfo->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(authInfo);

    auto *fpBar = new QHBoxLayout;
    m_fingerprint = new QLineEdit(m_client->savedFingerprint());
    m_fingerprint->setPlaceholderText("256-char hex fingerprint");
    m_fingerprint->setEchoMode(QLineEdit::Password);
    m_fingerprint->setFont(QFont("Consolas", 9));
    m_copyFpBtn = new QPushButton("Show");
    m_copyFpBtn->setCheckable(true);
    fpBar->addWidget(new QLabel("Fingerprint:"));
    fpBar->addWidget(m_fingerprint, 1);
    fpBar->addWidget(m_copyFpBtn);
    l->addLayout(fpBar);

    auto *loginBar = new QHBoxLayout;
    m_loginPass = new QLineEdit;
    m_loginPass->setPlaceholderText("Password (optional, set during setup)");
    m_loginPass->setEchoMode(QLineEdit::Password);
    m_setupBtn  = new QPushButton("First-time setup");
    m_setupBtn->setStyleSheet("background:#5a3a0a;color:white;padding:6px 12px");
    m_loginBtn  = new QPushButton("Log in");
    m_loginBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    m_logoutBtn = new QPushButton("Log out");
    loginBar->addWidget(new QLabel("Password:"));
    loginBar->addWidget(m_loginPass, 1);
    loginBar->addWidget(m_setupBtn);
    loginBar->addWidget(m_loginBtn);
    loginBar->addWidget(m_logoutBtn);
    l->addLayout(loginBar);

    // Claude.ai SSO — preferred over the raw API key. Tokens persist to
    // QSettings and auto-refresh on next API call when stale, so this is
    // a one-time login per Windows account.
    auto *claudeBar = new QHBoxLayout;
    m_claudeStatus = new QLabel;
    m_claudeStatus->setStyleSheet("color:#888;padding:0 6px");
    m_claudeSignInBtn  = new QPushButton("Sign in with Claude.ai");
    m_claudeSignInBtn->setStyleSheet("background:#5a2e7a;color:white;padding:6px 12px");
    m_claudeSignOutBtn = new QPushButton("Clear Claude tokens");
    auto refreshClaudeStatus = [this]() {
        if (OAuthHelper::hasFreshToken()) {
            QString email = QSettings("SHROUD","admin").value("anthropic_account_email").toString();
            qint64 exp = OAuthHelper::expiresAt();
            QDateTime dt = QDateTime::fromSecsSinceEpoch(exp);
            QString who = email.isEmpty() ? "Signed in" : "Signed in as " + email;
            m_claudeStatus->setText(who + " · token good until " + dt.toString("HH:mm"));
            m_claudeStatus->setStyleSheet("color:#7fff7f;padding:0 6px");
        } else if (!OAuthHelper::refreshTokenStored().isEmpty()) {
            m_claudeStatus->setText("Token stale — will auto-refresh on next chat send.");
            m_claudeStatus->setStyleSheet("color:#ffb74d;padding:0 6px");
        } else if (!m_anthropicKey->text().isEmpty()) {
            m_claudeStatus->setText("Using legacy API key (not SSO).");
            m_claudeStatus->setStyleSheet("color:#aaa;padding:0 6px");
        } else {
            m_claudeStatus->setText("Not signed in.");
            m_claudeStatus->setStyleSheet("color:#888;padding:0 6px");
        }
    };
    refreshClaudeStatus();
    claudeBar->addWidget(new QLabel("Claude.ai:"));
    claudeBar->addWidget(m_claudeStatus, 1);
    claudeBar->addWidget(m_claudeSignInBtn);
    claudeBar->addWidget(m_claudeSignOutBtn);
    l->addLayout(claudeBar);

    connect(m_claudeSignInBtn, &QPushButton::clicked, [this, refreshClaudeStatus]() {
        m_claudeSignInBtn->setEnabled(false);
        m_claudeStatus->setText("Opening browser…");
        // Helper outlives the browser handoff — same instance must do
        // the PKCE start + finishWithCode so the code_verifier is the
        // one Anthropic expects.
        auto *oa = new OAuthHelper(this);
        oa->start([this, oa, refreshClaudeStatus](bool ok, const QString &err) {
            m_claudeSignInBtn->setEnabled(true);
            if (ok) {
                refreshClaudeStatus();
            } else {
                m_claudeStatus->setText("Sign-in failed: " + err);
                m_claudeStatus->setStyleSheet("color:#ff8a8a;padding:0 6px");
            }
            oa->deleteLater();
        });
        // Prompt for the pasted code (Anthropic only honors the fixed
        // console.anthropic.com/oauth/code/callback redirect — there is
        // no localhost option, so the user copies the code off the
        // callback page and pastes it here).
        bool ok = false;
        QString code = QInputDialog::getText(this,
            "Paste the Anthropic auth code",
            "Your browser opened the Anthropic authorize page.\n"
            "After clicking Authorize, paste the code (or the full URL "
            "from the callback page) here.",
            QLineEdit::Normal, "", &ok);
        if (!ok || code.trimmed().isEmpty()) {
            m_claudeStatus->setText("Sign-in cancelled.");
            m_claudeSignInBtn->setEnabled(true);
            oa->deleteLater();
            return;
        }
        m_claudeStatus->setText("Exchanging code for tokens…");
        oa->finishWithCode(code);
    });
    connect(m_claudeSignOutBtn, &QPushButton::clicked, [refreshClaudeStatus]() {
        OAuthHelper::clear();
        refreshClaudeStatus();
    });

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
    connect(m_copyFpBtn, &QPushButton::toggled, [this](bool show) {
        m_fingerprint->setEchoMode(show ? QLineEdit::Normal : QLineEdit::Password);
        m_copyFpBtn->setText(show ? "Hide" : "Show");
    });
    connect(m_setupBtn, &QPushButton::clicked, [this]() {
        if (QMessageBox::warning(this, "First-time setup",
            "First-time setup mints a fingerprint that CANNOT be recovered. "
            "Only run this on a relay that has never been configured.\n\n"
            "Proceed?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
            return;
        m_setupBtn->setEnabled(false);
        m_status->setText("Requesting fingerprint mint…");
        m_client->adminFirstTimeSetup(
            [this](const QString &fp, const QString &err) {
                m_setupBtn->setEnabled(true);
                if (!fp.isEmpty()) {
                    m_fingerprint->setText(fp);
                    m_copyFpBtn->setChecked(true);
                    QApplication::clipboard()->setText(fp);
                    m_status->setText(
                        "Fingerprint minted and copied to clipboard. "
                        "Save it now — it cannot be recovered.");
                } else {
                    m_status->setText("Setup failed: " + err);
                }
            });
    });
    connect(m_loginBtn,  &QPushButton::clicked, [this]() {
        m_status->setText("Logging in…");
        m_loginBtn->setEnabled(false);
        m_client->adminLogin(m_fingerprint->text().trimmed(), m_loginPass->text(),
            [this](bool ok, const QString &err) {
                m_loginBtn->setEnabled(true);
                if (ok) {
                    m_status->setText("Logged in. Session + CSRF captured.");
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
