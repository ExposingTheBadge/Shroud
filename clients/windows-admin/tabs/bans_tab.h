#ifndef SHROUD_ADMIN_BANS_TAB_H
#define SHROUD_ADMIN_BANS_TAB_H
#include <QWidget>
class QTableWidget; class QLineEdit; class QPushButton; class QComboBox;
class AdminClient;

class BansTab : public QWidget {
    Q_OBJECT
public:
    explicit BansTab(AdminClient *client, QWidget *parent = nullptr);
public slots:
    void prefillUsername(const QString &username);
private slots:
    void refresh();
    void onAddBan();
    void onLiftSelected();
    void onLiftUserCascade();
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QLineEdit *m_inputValue;
    QLineEdit *m_inputReason;
    QComboBox *m_kindBox;
    QPushButton *m_addBtn, *m_liftBtn, *m_liftUserBtn, *m_refreshBtn;
};
#endif
