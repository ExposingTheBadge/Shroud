#ifndef SHROUD_ADMIN_DIAGNOSTICS_TAB_H
#define SHROUD_ADMIN_DIAGNOSTICS_TAB_H
#include <QWidget>
#include <QJsonArray>
class QTableWidget; QT_FORWARD_DECLARE_CLASS(QTextBrowser);
class QLineEdit; class QPushButton; class QLabel;
class QProcess;
class AdminClient;

class DiagnosticsTab : public QWidget {
    Q_OBJECT
public:
    explicit DiagnosticsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onPoll();
    void onSelectionChanged();
    void onProcessFinished(int code);
private:
    AdminClient *m_client;
    QLineEdit *m_keyfile;
    QTableWidget *m_table;
    QTextBrowser *m_detail;
    QLabel       *m_status;
    QPushButton  *m_pollBtn, *m_browseBtn;
    QProcess     *m_proc;
    QJsonArray    m_reports;
    QString       resolvePython() const;
};
#endif
