#ifndef SHROUD_ADMIN_ERRORS_TAB_H
#define SHROUD_ADMIN_ERRORS_TAB_H
#include <QWidget>
class QTableWidget; class QLineEdit; class QPushButton; class QLabel;
class AdminClient;

class ErrorsTab : public QWidget {
    Q_OBJECT
public:
    explicit ErrorsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
    void applyFilter(const QString &needle);
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QLineEdit    *m_search;
    QPushButton  *m_refreshBtn;
    QLabel       *m_count;
};
#endif
