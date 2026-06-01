#ifndef SHROUD_ADMIN_MULTISIG_TAB_H
#define SHROUD_ADMIN_MULTISIG_TAB_H
#include <QWidget>
class QLineEdit; class QPushButton; class QPlainTextEdit; class QLabel; class QComboBox;
class QProcess;
class AdminClient;

class MultisigTab : public QWidget {
    Q_OBJECT
public:
    explicit MultisigTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onLoadReleases();
    void onVerifyTag();
    void onProcessOutput();
    void onProcessFinished(int code);
private:
    AdminClient *m_client;
    QComboBox *m_tagBox;
    QLineEdit *m_repoBox;
    QPushButton *m_loadBtn, *m_verifyBtn;
    QPlainTextEdit *m_output;
    QLabel *m_status;
    QProcess *m_proc;
};
#endif
