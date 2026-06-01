#ifndef SHROUD_ADMIN_USER_DETAIL_DIALOG_H
#define SHROUD_ADMIN_USER_DETAIL_DIALOG_H
#include <QDialog>
class QTextBrowser; class QTableWidget; class QLabel; class QPushButton;
class AdminClient;

class UserDetailDialog : public QDialog {
    Q_OBJECT
public:
    UserDetailDialog(AdminClient *client, const QString &userId,
                     const QString &username, QWidget *parent = nullptr);
signals:
    void banUserRequested(const QString &username);
private slots:
    void refresh();
    void onBan();
    void onDelete();
private:
    AdminClient *m_client;
    QString m_userId, m_username;
    QLabel *m_title, *m_meta;
    QTableWidget *m_deviceTable;
    QTextBrowser *m_raw;
    QPushButton *m_banBtn, *m_delBtn, *m_refreshBtn, *m_closeBtn;
};
#endif
