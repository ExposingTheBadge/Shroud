#include "admin_window.h"
#include "tabs/federation_tab.h"
#include "tabs/stats_tab.h"
#include "tabs/controls_tab.h"
#include "tabs/logs_tab.h"
#include "tabs/users_tab.h"
#include "tabs/bans_tab.h"
#include "tabs/diagnostics_tab.h"
#include "tabs/manifest_tab.h"
#include "tabs/relay_ssh_tab.h"
#include "tabs/claude_chat_tab.h"
#include "tabs/settings_tab.h"
#include "tabs/errors_tab.h"
#include "tabs/devices_tab.h"
#include "tabs/audit_tab.h"
#include <QVBoxLayout>
#include <QApplication>
#include <QIcon>

AdminWindow::AdminWindow(QWidget *parent) : QMainWindow(parent) {
    setWindowTitle("SHROUD Admin — operator");
    setWindowIcon(QIcon(":/shroud-admin.png"));
    resize(1280, 820);

    m_client     = new AdminClient(this);

    m_tabs       = new QTabWidget(this);
    m_federation = new FederationTab(m_client);
    m_stats      = new StatsTab(m_client);
    m_controls   = new ControlsTab(m_client);
    m_logs       = new LogsTab(m_client);
    m_users      = new UsersTab(m_client);
    m_bans       = new BansTab(m_client);
    m_diag       = new DiagnosticsTab(m_client);
    m_manifest   = new ManifestTab(m_client);
    m_ssh        = new RelaySshTab(m_client);
    m_claude     = new ClaudeChatTab(m_client);
    m_settings   = new SettingsTab(m_client);
    m_errors     = new ErrorsTab(m_client);
    m_devices    = new DevicesTab(m_client);
    m_audit      = new AuditTab(m_client);

    m_tabs->addTab(m_federation, "Federation");
    m_tabs->addTab(m_stats,      "Stats");
    m_tabs->addTab(m_controls,   "Controls");
    m_tabs->addTab(m_logs,       "Logs");
    m_tabs->addTab(m_users,      "Users");
    m_tabs->addTab(m_devices,    "Devices");
    m_tabs->addTab(m_bans,       "Bans");
    m_tabs->addTab(m_audit,      "Audit");
    m_tabs->addTab(m_diag,       "Diagnostics");
    m_tabs->addTab(m_manifest,   "Manifest");
    m_tabs->addTab(m_ssh,        "Relays (SSH)");
    m_tabs->addTab(m_claude,     "Claude Chat");
    m_tabs->addTab(m_errors,     "Error Codes");
    m_tabs->addTab(m_settings,   "Settings");

    setCentralWidget(m_tabs);

    m_relayLbl    = new QLabel("relay: " + m_client->relayUrl(), this);
    m_wsLbl       = new QLabel("WS: disconnected", this);
    m_userBadge   = new QLabel("users —", this);
    m_deviceBadge = new QLabel("devices —", this);
    m_errorBadge  = new QLabel("errs —", this);
    m_userBadge->setStyleSheet("color:#7fbfff;padding:0 6px");
    m_deviceBadge->setStyleSheet("color:#7fff7f;padding:0 6px");
    m_errorBadge->setStyleSheet("color:#ff8a8a;padding:0 6px");
    statusBar()->addWidget(m_relayLbl, 1);
    statusBar()->addPermanentWidget(m_userBadge);
    statusBar()->addPermanentWidget(m_deviceBadge);
    statusBar()->addPermanentWidget(m_errorBadge);
    statusBar()->addPermanentWidget(m_wsLbl);

    connect(m_stats, &StatsTab::countsUpdated, this,
            [this](int users, int devices, int, int errors) {
                m_userBadge->setText(QString("users %1").arg(users));
                m_deviceBadge->setText(QString("devices %1").arg(devices));
                m_errorBadge->setText(QString("errs %1").arg(errors));
            });

    // Devices → ban context menu → BansTab
    connect(m_devices, &DevicesTab::banHwidRequested, this, [this](const QString &hwid) {
        m_bans->prefillUsername(hwid);
        m_tabs->setCurrentWidget(m_bans);
    });

    connect(m_client, &AdminClient::wsConnected,    this, &AdminWindow::onWsConnected);
    connect(m_client, &AdminClient::wsDisconnected, this, &AdminWindow::onWsDisconnected);
    connect(m_settings, &SettingsTab::relayUrlChanged, this, &AdminWindow::onRelayUrlChanged);

    // When the operator picks "Ban user" from the Users tab context menu,
    // jump to the Bans tab with the username pre-filled.
    connect(m_users, &UsersTab::banUserRequested, this, [this](const QString &u) {
        m_bans->prefillUsername(u);
        m_tabs->setCurrentWidget(m_bans);
    });

    // Auto-connect WS if we already have a session cookie.
    if (!m_client->adminSessionCookie().isEmpty()) {
        m_client->connectAdminWs();
    }
}

void AdminWindow::onWsConnected()    { m_wsLbl->setText("WS: connected"); }
void AdminWindow::onWsDisconnected() { m_wsLbl->setText("WS: disconnected"); }

void AdminWindow::onRelayUrlChanged(const QString &url) {
    m_client->setRelayUrl(url);
    m_relayLbl->setText("relay: " + url);
    // reconnect WS on the new relay
    m_client->disconnectAdminWs();
    if (!m_client->adminSessionCookie().isEmpty()) {
        m_client->connectAdminWs();
    }
}
