#ifndef SHROUD_ADMIN_RELAY_SSH_TAB_H
#define SHROUD_ADMIN_RELAY_SSH_TAB_H
#include <QWidget>
class QPlainTextEdit; class QPushButton; class QLineEdit;
class AdminClient;

// Runs maintenance commands on the relay host over SSH. The host, user
// and key are settings (QSettings), not compiled in: the four AWS relays
// this tab used to target are gone.
class RelaySshTab : public QWidget {
    Q_OBJECT
public:
    explicit RelaySshTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void run(const QString &cmd, const QString &label);
    void runCustom();
    void browseKey();
    void saveTarget();
private:
    AdminClient *m_client;
    QPlainTextEdit *m_output;
    QLineEdit *m_hostEdit, *m_userEdit, *m_keyEdit, *m_customCmd;
    QPushButton *m_customRunBtn;
};
#endif
