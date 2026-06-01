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

    auto addAction = [&](const QString &lbl, const QString &slug,
                         const QString &confirm, const char *style) {
        auto *b = new QPushButton(lbl);
        b->setMinimumHeight(40);
        if (style) b->setStyleSheet(style);
        connect(b, &QPushButton::clicked,
                [this, slug, confirm]() { runAction(slug, confirm); });
        grid->addWidget(b, row / 3, row % 3);
        row++;
        return b;
    };

    // Toggles — slot keeps a member pointer so refreshFlags() can rename
    // the button to reflect current on/off state ("Maintenance: OFF").
    m_mntBtn = addAction("Maintenance —", "",
        "Flip server-wide maintenance mode. Send/receive paused for all users.", nullptr);
    disconnect(m_mntBtn, &QPushButton::clicked, nullptr, nullptr);
    connect(m_mntBtn, &QPushButton::clicked, [this]() {
        runToggle("maintenance", "maintenance_mode",
                  "Flip server-wide maintenance mode. Send/receive paused for all users.");
    });

    m_regBtn = addAction("Registration —", "",
        "Flip whether new user signups are allowed.", nullptr);
    disconnect(m_regBtn, &QPushButton::clicked, nullptr, nullptr);
    connect(m_regBtn, &QPushButton::clicked, [this]() {
        runToggle("registration", "registration_enabled",
                  "Flip whether new user signups are allowed.");
    });

    m_onionBtn = addAction("Onion-Only —", "",
        "Flip whether the relay accepts clearnet (non-Tor) connections.", nullptr);
    disconnect(m_onionBtn, &QPushButton::clicked, nullptr, nullptr);
    connect(m_onionBtn, &QPushButton::clicked, [this]() {
        runToggle("onion-only", "onion_only",
                  "Flip whether the relay accepts clearnet (non-Tor) connections.");
    });

    addAction("VACUUM DB",            "vacuum",            "Compact the SQLite database. Briefly locks the DB.",                    "background:#5a3a0a;color:white");
    addAction("Purge Files",          "purge-files",       "Delete expired and already-downloaded files from disk.",                "background:#5a3a0a;color:white");
    addAction("Clear ECDH Cache",     "clear-ecdh",        "Drop all ephemeral ECDH session keys. In-flight handshakes will retry.", "background:#5a3a0a;color:white");
    addAction("Reset Rate Limits",    "wipe-rate-limits",  "Reset every per-IP rate-limit bucket to zero.",                         "background:#5a3a0a;color:white");
    addAction("Kill Other Admins",    "kill-sessions",     "Sign out every OTHER admin session except this one.",                   "background:#7a1a1a;color:white");
    addAction("Drop Undelivered",     "clear-undelivered", "Drop every undelivered message queued on the relay.",                   "background:#7a1a1a;color:white");

    l->addLayout(grid);
    l->addStretch();
    refreshFlags();
}

void ControlsTab::applyToggleLabel(QPushButton *btn, const QString &label, bool on) {
    btn->setText(QString("%1: %2").arg(label, on ? "ON" : "OFF"));
    btn->setStyleSheet(on ? "background:#2e7d32;color:white"
                          : "background:#444;color:#cfcfcf");
}

void ControlsTab::runToggle(const QString &slug, const QString &flagKey,
                            const QString &confirmMsg) {
    bool current = (flagKey == "registration_enabled") ? m_registrationEnabled
                 : (flagKey == "maintenance_mode")     ? m_maintenanceMode
                                                       : m_onionOnly;
    bool desired = !current;
    auto ans = QMessageBox::warning(this, "Confirm toggle",
        QString("%1\n\nSet to %2?").arg(confirmMsg).arg(desired ? "ON" : "OFF"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (ans != QMessageBox::Yes) return;
    m_status->setText(QString("Setting %1=%2…").arg(flagKey).arg(desired ? "1" : "0"));
    QJsonObject body;
    body["enabled"] = desired;
    m_client->postJson(QString("/api/v1/admin/control/%1").arg(slug), body,
        [this, flagKey, desired](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                m_status->setText("ERROR: " + err);
                return;
            }
            Q_UNUSED(d);
            m_status->setText(QString("OK: %1=%2").arg(flagKey).arg(desired ? "1" : "0"));
            refreshFlags();
        });
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
            m_registrationEnabled = o.value("registration_enabled").toBool();
            m_maintenanceMode     = o.value("maintenance_mode").toBool();
            m_onionOnly           = o.value("onion_only").toBool();
            applyToggleLabel(m_mntBtn,   "Maintenance",  m_maintenanceMode);
            applyToggleLabel(m_regBtn,   "Registration", m_registrationEnabled);
            applyToggleLabel(m_onionBtn, "Onion-Only",   m_onionOnly);
        });
}
