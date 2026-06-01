// admin_window.h — top-level MainWindow with tab widget.
//
// PRIVATE — see ../README.md.
#ifndef SHROUD_ADMIN_WINDOW_H
#define SHROUD_ADMIN_WINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QStatusBar>
#include <QLabel>
#include "admin_client.h"

class FederationTab;
class StatsTab;
class ControlsTab;
class LogsTab;
class UsersTab;
class BansTab;
class DiagnosticsTab;
class ManifestTab;
class RelaySshTab;
class ClaudeChatTab;
class SettingsTab;
class ErrorsTab;
class DevicesTab;
class AuditTab;
class IdentityTab;

class AdminWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit AdminWindow(QWidget *parent = nullptr);

private slots:
    void onWsConnected();
    void onWsDisconnected();
    void onRelayUrlChanged(const QString &url);

private:
    AdminClient     *m_client;
    QTabWidget      *m_tabs;
    QLabel          *m_relayLbl;
    QLabel          *m_wsLbl;

    FederationTab   *m_federation;
    StatsTab        *m_stats;
    ControlsTab     *m_controls;
    LogsTab         *m_logs;
    UsersTab        *m_users;
    BansTab         *m_bans;
    DiagnosticsTab  *m_diag;
    ManifestTab     *m_manifest;
    RelaySshTab     *m_ssh;
    ClaudeChatTab   *m_claude;
    SettingsTab     *m_settings;
    ErrorsTab       *m_errors;
    DevicesTab      *m_devices;
    AuditTab        *m_audit;
    IdentityTab     *m_identity;

    QLabel *m_userBadge, *m_deviceBadge, *m_errorBadge;
};

#endif
