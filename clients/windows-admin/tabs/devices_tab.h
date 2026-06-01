#ifndef SHROUD_ADMIN_DEVICES_TAB_H
#define SHROUD_ADMIN_DEVICES_TAB_H
#include <QWidget>
class QTableWidget; class QLineEdit; class QPushButton; class QLabel;
class AdminClient;

class DevicesTab : public QWidget {
    Q_OBJECT
public:
    explicit DevicesTab(AdminClient *client, QWidget *parent = nullptr);
signals:
    void banHwidRequested(const QString &hwid);
private slots:
    void refresh();
    void onKillSelected();
    void applyFilter(const QString &needle);
private:
    AdminClient *m_client;
    QTableWidget *m_table;
    QLineEdit *m_search;
    QPushButton *m_refreshBtn, *m_killBtn;
    QLabel *m_count;
};
#endif
