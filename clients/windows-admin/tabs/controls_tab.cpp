#include "controls_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QJsonObject>

ControlsTab::ControlsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    m_status = new QLabel("Idle");
    m_status->setStyleSheet("color:#888;padding:6px");
    l->addWidget(m_status);

    auto *grid = new QGridLayout;
    grid->setSpacing(10);
    int row = 0;

    auto add = [&](const QString &lbl, const QString &slug,
                   const QString &confirm, const char *style) {
        auto *b = new QPushButton(lbl);
        b->setMinimumHeight(40);
        if (style) b->setStyleSheet(style);
        connect(b, &QPushButton::clicked,
                [this, slug, confirm]() { runAction(slug, confirm); });
        grid->addWidget(b, row / 3, row % 3);
        row++;
    };

    add("Toggle Maintenance",   "maintenance",       "Flip server-wide maintenance mode. Send/receive paused for all users.", nullptr);
    add("Toggle Registration",  "registration",      "Flip whether new user signups are allowed.",                            nullptr);
    add("Toggle Onion-Only",    "onion-only",        "Flip whether the relay accepts clearnet (non-Tor) connections.",       nullptr);
    add("VACUUM DB",            "vacuum",            "Compact the SQLite database. Briefly locks the DB.",                    "background:#5a3a0a;color:white");
    add("Purge Files",          "purge-files",       "Delete expired and already-downloaded files from disk.",                "background:#5a3a0a;color:white");
    add("Clear ECDH Cache",     "clear-ecdh",        "Drop all ephemeral ECDH session keys. In-flight handshakes will retry.", "background:#5a3a0a;color:white");
    add("Reset Rate Limits",    "wipe-rate-limits",  "Reset every per-IP rate-limit bucket to zero.",                         "background:#5a3a0a;color:white");
    add("Kill Other Admins",    "kill-sessions",     "Sign out every OTHER admin session except this one.",                   "background:#7a1a1a;color:white");
    add("Drop Undelivered",     "clear-undelivered", "Drop every undelivered message queued on the relay.",                   "background:#7a1a1a;color:white");

    l->addLayout(grid);
    l->addStretch();
    refreshFlags();
}

void ControlsTab::runAction(const QString &slug, const QString &confirmMsg) {
    auto ans = QMessageBox::warning(
        this, "Confirm action", confirmMsg + "\n\nProceed?",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (ans != QMessageBox::Yes) return;

    m_status->setText("Running: " + slug);
    m_client->postJson(QString("/api/v1/admin/control/%1").arg(slug), QJsonObject(),
        [this, slug](const QJsonDocument &, const QString &err) {
            if (err.isEmpty()) m_status->setText("OK: " + slug);
            else               m_status->setText("ERROR " + slug + ": " + err);
            refreshFlags();
        });
}

void ControlsTab::refreshFlags() {
    m_client->getJson("/api/v1/admin/flags",
        [this](const QJsonDocument &d, const QString &) {
            if (!d.isObject()) return;
            auto o = d.object();
            // Could update toggle visuals here once the buttons render flag-aware.
            Q_UNUSED(o);
        });
}
