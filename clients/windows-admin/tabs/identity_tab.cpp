#include "identity_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QGuiApplication>
#include <QClipboard>
#include <QGroupBox>
#include <QJsonObject>

IdentityTab::IdentityTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Long-lived <b>server identity</b> blob. Clients pin <i>this</i> "
        "fingerprint on first connect (TOFU) and refuse to talk to any "
        "relay presenting a different identity afterwards. The suite is "
        "a triple-hybrid: <code>Ed25519 + ML-DSA-87 + SPHINCS+</code>. "
        "Rotating the identity is a hard break — only do it via the "
        "documented multisig rotation procedure.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:8px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *fpGroup = new QGroupBox("Pin fingerprint");
    auto *fpL = new QVBoxLayout(fpGroup);
    m_fingerprint = new QLabel("—");
    m_fingerprint->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_fingerprint->setStyleSheet(
        "QLabel { font-family:Consolas,monospace; font-size:14px;"
        " font-weight:600; color:#ffb74d; padding:8px 14px;"
        " background:#1a1a1a; border:1px solid #333; border-radius:4px; }");
    m_fingerprint->setWordWrap(true);
    fpL->addWidget(m_fingerprint);
    auto *fpBar = new QHBoxLayout;
    m_copyFpBtn = new QPushButton("Copy fingerprint");
    m_refreshBtn = new QPushButton("Refresh");
    fpBar->addStretch();
    fpBar->addWidget(m_copyFpBtn);
    fpBar->addWidget(m_refreshBtn);
    fpL->addLayout(fpBar);
    l->addWidget(fpGroup);

    auto *metaGroup = new QGroupBox("Identity metadata");
    auto *metaL = new QFormLayout(metaGroup);
    m_suite     = new QLabel("—"); m_suite->setStyleSheet("font-family:Consolas,monospace;color:#cfcfcf");
    m_createdAt = new QLabel("—"); m_createdAt->setStyleSheet("font-family:Consolas,monospace;color:#cfcfcf");
    metaL->addRow("Suite",      m_suite);
    metaL->addRow("Created at", m_createdAt);
    l->addWidget(metaGroup);

    auto *pkGroup = new QGroupBox("Public-key blob (hex)");
    auto *pkL = new QVBoxLayout(pkGroup);
    m_pubkeyBlob = new QPlainTextEdit;
    m_pubkeyBlob->setReadOnly(true);
    m_pubkeyBlob->setStyleSheet(
        "font-family:Consolas,monospace; font-size:11px;"
        " background:#0a0a0a; color:#cfcfcf;");
    m_pubkeyBlob->setMaximumHeight(180);
    pkL->addWidget(m_pubkeyBlob);
    auto *pkBar = new QHBoxLayout;
    m_copyPkBtn = new QPushButton("Copy pubkey hex");
    pkBar->addStretch();
    pkBar->addWidget(m_copyPkBtn);
    pkL->addLayout(pkBar);
    l->addWidget(pkGroup, 1);

    connect(m_copyFpBtn, &QPushButton::clicked, this, &IdentityTab::copyFingerprint);
    connect(m_copyPkBtn, &QPushButton::clicked, this, &IdentityTab::copyPubkey);
    connect(m_refreshBtn,&QPushButton::clicked, this, &IdentityTab::refresh);
    connect(&m_timer, &QTimer::timeout, this, &IdentityTab::refresh);
    m_timer.start(60'000);

    refresh();
}

void IdentityTab::refresh() {
    m_client->getJson("/api/v1/server-identity",
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                m_fingerprint->setText("identity not loaded: " + err);
                return;
            }
            auto o = d.object();
            m_fingerprint->setText(o.value("fingerprint").toString("(none)"));
            m_suite->setText(o.value("suite").toString("(unknown)"));
            m_createdAt->setText(o.value("created_at").toString("(unknown)"));
            m_pubkeyBlob->setPlainText(o.value("pubkey_blob").toString("(missing)"));
        });
}

void IdentityTab::copyFingerprint() {
    QGuiApplication::clipboard()->setText(m_fingerprint->text());
}

void IdentityTab::copyPubkey() {
    QGuiApplication::clipboard()->setText(m_pubkeyBlob->toPlainText());
}
