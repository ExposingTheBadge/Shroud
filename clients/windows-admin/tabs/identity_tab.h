#ifndef SHROUD_ADMIN_IDENTITY_TAB_H
#define SHROUD_ADMIN_IDENTITY_TAB_H
#include <QWidget>
#include <QTimer>
class QLabel; class QPlainTextEdit; class QPushButton;
class AdminClient;

class IdentityTab : public QWidget {
    Q_OBJECT
public:
    explicit IdentityTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
    void copyFingerprint();
    void copyPubkey();
private:
    AdminClient *m_client;
    QLabel       *m_fingerprint;
    QLabel       *m_suite, *m_createdAt;
    QPlainTextEdit *m_pubkeyBlob;
    QPushButton  *m_copyFpBtn, *m_copyPkBtn, *m_refreshBtn;
    QTimer        m_timer;
};
#endif
