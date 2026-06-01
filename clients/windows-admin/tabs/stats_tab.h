#ifndef SHROUD_ADMIN_STATS_TAB_H
#define SHROUD_ADMIN_STATS_TAB_H
#include <QWidget>
#include <QTimer>
class QPlainTextEdit;
class AdminClient;

class StatsTab : public QWidget {
    Q_OBJECT
public:
    explicit StatsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
private:
    AdminClient *m_client;
    QPlainTextEdit *m_dump;
    QTimer m_timer;
};
#endif
