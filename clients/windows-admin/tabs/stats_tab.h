#ifndef SHROUD_ADMIN_STATS_TAB_H
#define SHROUD_ADMIN_STATS_TAB_H
#include <QWidget>
#include <QTimer>
class QGridLayout; class QLabel; class QFrame; class QVBoxLayout;
class AdminClient;
class SparklineWidget;

class StatsTab : public QWidget {
    Q_OBJECT
public:
    explicit StatsTab(AdminClient *client, QWidget *parent = nullptr);
signals:
    void countsUpdated(int users, int devices, int messages24h, int errors);
private slots:
    void refresh();
private:
    AdminClient *m_client;
    QTimer m_timer;

    QLabel *kvVal(const QString &label, const QString &color = "#e0e0e0");
    QFrame *makeCard(const QString &title, QVBoxLayout *&inner);

    // Cards
    QLabel *m_userCount, *m_proCount, *m_freeCount;
    QLabel *m_deviceCount, *m_activeNow, *m_active5min;
    QLabel *m_msgs1h, *m_msgs24h, *m_bytes24h;
    QLabel *m_avgLatency, *m_minLatency, *m_maxLatency;
    QLabel *m_errorsTotal, *m_failedLogins, *m_coverCount, *m_coverBytes;
    QLabel *m_onionPct, *m_clearPct, *m_anonPending, *m_diagPending;
    QLabel *m_relayVersion, *m_relayUptime, *m_relayGitSha, *m_relayDisk;

    SparklineWidget *m_sparkReqs, *m_sparkErrs, *m_sparkMsgs, *m_sparkActive;
    void refreshSeries();
};
#endif
