#ifndef SHROUD_ADMIN_BACKUP_TAB_H
#define SHROUD_ADMIN_BACKUP_TAB_H
#include <QWidget>
class QTableWidget; class QPushButton; class QLabel; class QPlainTextEdit;
class QProcess;
class AdminClient;

class BackupTab : public QWidget {
    Q_OBJECT
public:
    explicit BackupTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
    void onTakeBackup();
    void onDownload();
    void onRestore();
    void onDelete();
    void onProcessOutput();
    void onProcessFinished(int code);
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QPushButton  *m_takeBtn, *m_dlBtn, *m_restoreBtn, *m_delBtn, *m_refreshBtn;
    QLabel       *m_status;
    QPlainTextEdit *m_log;
    QProcess     *m_proc;
};
#endif
