#ifndef SHROUD_ADMIN_DIAGNOSTICS_TAB_H
#define SHROUD_ADMIN_DIAGNOSTICS_TAB_H
#include <QWidget>
class QPlainTextEdit; class QLineEdit; class QPushButton;
class QProcess;
class AdminClient;

class DiagnosticsTab : public QWidget {
    Q_OBJECT
public:
    explicit DiagnosticsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onPoll();
    void onProcessOutput();
    void onProcessFinished(int code);
private:
    AdminClient *m_client;
    QLineEdit *m_keyfile;
    QPlainTextEdit *m_output;
    QPushButton *m_pollBtn;
    QProcess *m_proc;
};
#endif
