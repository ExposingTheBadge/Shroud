#ifndef SHROUD_ADMIN_SETTINGS_TAB_H
#define SHROUD_ADMIN_SETTINGS_TAB_H
#include <QWidget>
class QLineEdit; class QPushButton; class QLabel;
class AdminClient;

class SettingsTab : public QWidget {
    Q_OBJECT
public:
    explicit SettingsTab(AdminClient *client, QWidget *parent = nullptr);
signals:
    void relayUrlChanged(const QString &url);
private slots:
    void onSave();
    void onTestRelay();
    void onTestAnthropic();
private:
    AdminClient *m_client;
    QLineEdit *m_relayUrl, *m_sessionCookie, *m_anthropicKey;
    QLineEdit *m_socksProxy;
    QLineEdit *m_diagKeyfile, *m_manifestKeyfile;
    QLineEdit   *m_fingerprint;
    QLineEdit   *m_loginPass;
    QLabel      *m_status;
    QPushButton *m_saveBtn, *m_testRelayBtn, *m_testAnthropicBtn;
    QPushButton *m_setupBtn, *m_loginBtn, *m_logoutBtn, *m_copyFpBtn;
};
#endif
