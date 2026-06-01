#ifndef SHROUD_ADMIN_AUDIT_TAB_H
#define SHROUD_ADMIN_AUDIT_TAB_H
#include <QWidget>
#include <QTimer>
class QTableWidget; class QLineEdit; class QPushButton; class QLabel; class QComboBox;
class AdminClient;
class QJsonObject;

class AuditTab : public QWidget {
    Q_OBJECT
public:
    explicit AuditTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
    void onWsEvent(const QJsonObject &ev);
    void applyFilter();
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QLineEdit *m_search;
    QComboBox *m_actionFilter;
    QPushButton *m_refreshBtn;
    QLabel *m_count;
};
#endif
