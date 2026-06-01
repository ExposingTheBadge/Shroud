#ifndef SHROUD_ADMIN_USERS_TAB_H
#define SHROUD_ADMIN_USERS_TAB_H
#include <QWidget>
class QTableWidget; class QLineEdit; class QPushButton;
class AdminClient;

class UsersTab : public QWidget {
    Q_OBJECT
public:
    explicit UsersTab(AdminClient *client, QWidget *parent = nullptr);
signals:
    void banUserRequested(const QString &username);  // jumped to BansTab
private slots:
    void refresh();
    void onBanSelected();
    void onDeleteSelected();
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QLineEdit *m_search;
    QPushButton *m_refreshBtn, *m_banBtn, *m_deleteBtn;
};
#endif
