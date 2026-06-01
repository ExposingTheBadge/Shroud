#include "stats_tab.h"
#include "../admin_client.h"
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFrame>
#include <QScrollArea>
#include <QJsonObject>
#include <QJsonArray>

static QString humanUptime(qint64 s) {
    if (s <= 0) return "—";
    qint64 d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
    if (d > 0) return QString("%1d %2h").arg(d).arg(h);
    if (h > 0) return QString("%1h %2m").arg(h).arg(m);
    return QString("%1m").arg(m);
}

static QString humanBytes(qint64 b) {
    if (b < 1024) return QString::number(b) + " B";
    if (b < 1024 * 1024) return QString::number(b / 1024.0, 'f', 1) + " KB";
    if (b < 1024LL * 1024 * 1024) return QString::number(b / (1024.0 * 1024), 'f', 1) + " MB";
    return QString::number(b / (1024.0 * 1024 * 1024), 'f', 2) + " GB";
}

QLabel *StatsTab::kvVal(const QString &label, const QString &color) {
    auto *l = new QLabel(label);
    l->setStyleSheet(QString("font-size:24px;font-weight:700;color:%1;font-family:Consolas,monospace").arg(color));
    return l;
}

QFrame *StatsTab::makeCard(const QString &title, QVBoxLayout *&inner) {
    auto *f = new QFrame;
    f->setFrameShape(QFrame::StyledPanel);
    f->setStyleSheet("QFrame { background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:10px; }");
    f->setMinimumSize(240, 130);
    auto *outer = new QVBoxLayout(f);
    outer->setSpacing(2);
    auto *tl = new QLabel(title);
    tl->setStyleSheet("color:#888;font-size:10px;text-transform:uppercase;letter-spacing:1px;border:none;padding:0");
    outer->addWidget(tl);
    inner = outer;
    return f;
}

StatsTab::StatsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);

    auto *scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setStyleSheet("QScrollArea { border:none; }");
    outer->addWidget(scroll);

    auto *content = new QWidget;
    scroll->setWidget(content);
    auto *grid = new QGridLayout(content);
    grid->setSpacing(10);

    int r = 0;

    // ─── Relay card ──────────────────────────────────────────────
    QVBoxLayout *l_relay;
    auto *relayCard = makeCard("This relay", l_relay);
    m_relayVersion = kvVal("—", "#ffb74d");
    m_relayUptime  = new QLabel("uptime —");
    m_relayUptime->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    m_relayGitSha  = new QLabel("git —");
    m_relayGitSha->setStyleSheet("color:#666;font-size:10px;font-family:Consolas,monospace;border:none;padding:0");
    m_relayDisk    = new QLabel("disk —");
    m_relayDisk->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_relay->addWidget(m_relayVersion);
    l_relay->addWidget(m_relayUptime);
    l_relay->addWidget(m_relayGitSha);
    l_relay->addWidget(m_relayDisk);
    l_relay->addStretch();
    grid->addWidget(relayCard, r, 0);

    // ─── Users card ──────────────────────────────────────────────
    QVBoxLayout *l_users;
    auto *usersCard = makeCard("Users", l_users);
    m_userCount = kvVal("—");
    m_proCount  = new QLabel("pro —");   m_proCount->setStyleSheet("color:#7fbfff;font-family:Consolas,monospace;border:none;padding:0");
    m_freeCount = new QLabel("free —");  m_freeCount->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_users->addWidget(m_userCount);
    l_users->addWidget(m_proCount);
    l_users->addWidget(m_freeCount);
    l_users->addStretch();
    grid->addWidget(usersCard, r, 1);

    // ─── Devices card ─────────────────────────────────────────────
    QVBoxLayout *l_devices;
    auto *devicesCard = makeCard("Devices", l_devices);
    m_deviceCount = kvVal("—");
    m_activeNow   = new QLabel("active now —");   m_activeNow->setStyleSheet("color:#7fff7f;font-family:Consolas,monospace;border:none;padding:0");
    m_active5min  = new QLabel("active 5min —");  m_active5min->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_devices->addWidget(m_deviceCount);
    l_devices->addWidget(m_activeNow);
    l_devices->addWidget(m_active5min);
    l_devices->addStretch();
    grid->addWidget(devicesCard, r++, 2);

    // ─── Messages cards ──────────────────────────────────────────
    QVBoxLayout *l_msgs;
    auto *msgsCard = makeCard("Messages — last 24h", l_msgs);
    m_msgs24h  = kvVal("—", "#7fff7f");
    m_msgs1h   = new QLabel("1h —"); m_msgs1h->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    m_bytes24h = new QLabel("bytes —"); m_bytes24h->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_msgs->addWidget(m_msgs24h);
    l_msgs->addWidget(m_msgs1h);
    l_msgs->addWidget(m_bytes24h);
    l_msgs->addStretch();
    grid->addWidget(msgsCard, r, 0);

    QVBoxLayout *l_lat;
    auto *latCard = makeCard("Latency — last hour", l_lat);
    m_avgLatency = kvVal("—", "#ffb74d");
    m_minLatency = new QLabel("min —"); m_minLatency->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    m_maxLatency = new QLabel("max —"); m_maxLatency->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_lat->addWidget(m_avgLatency);
    l_lat->addWidget(m_minLatency);
    l_lat->addWidget(m_maxLatency);
    l_lat->addStretch();
    grid->addWidget(latCard, r, 1);

    QVBoxLayout *l_err;
    auto *errCard = makeCard("Errors", l_err);
    m_errorsTotal  = kvVal("—", "#ff7f7f");
    m_failedLogins = new QLabel("failed admin logins 24h —");
    m_failedLogins->setStyleSheet("color:#ff8a8a;font-family:Consolas,monospace;font-size:11px;border:none;padding:0");
    l_err->addWidget(m_errorsTotal);
    l_err->addWidget(m_failedLogins);
    l_err->addStretch();
    grid->addWidget(errCard, r++, 2);

    // ─── Cover + transport + pending ─────────────────────────────
    QVBoxLayout *l_cover;
    auto *coverCard = makeCard("Cover traffic", l_cover);
    m_coverCount = kvVal("—", "#a0a0ff");
    m_coverBytes = new QLabel("bytes —"); m_coverBytes->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_cover->addWidget(m_coverCount);
    l_cover->addWidget(m_coverBytes);
    l_cover->addStretch();
    grid->addWidget(coverCard, r, 0);

    QVBoxLayout *l_xport;
    auto *xportCard = makeCard("Transport split", l_xport);
    m_onionPct = kvVal("—", "#ffb74d");
    m_clearPct = new QLabel("clearnet —"); m_clearPct->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_xport->addWidget(new QLabel("via .onion"));
    l_xport->addWidget(m_onionPct);
    l_xport->addWidget(m_clearPct);
    l_xport->addStretch();
    grid->addWidget(xportCard, r, 1);

    QVBoxLayout *l_pend;
    auto *pendCard = makeCard("Pending queues", l_pend);
    m_anonPending = kvVal("—", "#7fbfff");
    m_diagPending = new QLabel("diag reports —"); m_diagPending->setStyleSheet("color:#aaa;font-family:Consolas,monospace;border:none;padding:0");
    l_pend->addWidget(new QLabel("anon msgs"));
    l_pend->addWidget(m_anonPending);
    l_pend->addWidget(m_diagPending);
    l_pend->addStretch();
    grid->addWidget(pendCard, r++, 2);

    grid->setRowStretch(r, 1);

    connect(&m_timer, &QTimer::timeout, this, &StatsTab::refresh);
    m_timer.start(6'000);
    refresh();
}

void StatsTab::refresh() {
    // Pull /api/v1/admin/stats/overview (rich), /api/v1/relay-stats (no auth),
    // and /api/v1/admin/stats/users (counts).
    m_client->getJson("/api/v1/relay-stats",
        [this](const QJsonDocument &d, const QString &) {
            if (!d.isObject()) return;
            auto o = d.object();
            m_relayVersion->setText("v" + o.value("version").toString("?"));
            m_relayUptime->setText("uptime: "
                + humanUptime(o.value("uptime_seconds").toVariant().toLongLong()));
            m_relayGitSha->setText("git: " + o.value("git_sha").toString("?"));
            auto cap = o.value("capacity").toObject();
            m_relayDisk->setText(QString("disk: %1%   load: %2 / %3 / %4")
                .arg(cap.value("disk_used_pct").toDouble(), 0, 'f', 1)
                .arg(cap.value("load_avg").toArray().at(0).toDouble(), 0, 'f', 2)
                .arg(cap.value("load_avg").toArray().at(1).toDouble(), 0, 'f', 2)
                .arg(cap.value("load_avg").toArray().at(2).toDouble(), 0, 'f', 2));
            auto traf = o.value("traffic").toObject();
            m_anonPending->setText(QString::number(
                traf.value("anon_messages_pending").toVariant().toLongLong()));
            m_diagPending->setText("diag reports: "
                + QString::number(traf.value("diag_reports_pending").toVariant().toLongLong()));
        });

    m_client->getJson("/api/v1/admin/stats/overview",
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty() || !d.isObject()) return;
            auto o = d.object();
            m_userCount->setText(QString::number(o.value("user_count").toInt()));
            m_proCount->setText("pro " + QString::number(o.value("pro_count").toInt()));
            m_freeCount->setText("free " + QString::number(o.value("free_count").toInt()));
            m_deviceCount->setText(QString::number(o.value("device_count").toInt()));
            m_activeNow->setText("active now " + QString::number(o.value("active_now").toInt()));
            m_active5min->setText("active 5min " + QString::number(o.value("active_5min").toInt()));
            m_msgs1h->setText("1h " + QString::number(o.value("msgs_1h").toVariant().toLongLong()));
            m_msgs24h->setText(QString::number(o.value("msgs_24h").toVariant().toLongLong()));
            m_bytes24h->setText("bytes " + humanBytes(o.value("bytes_24h").toVariant().toLongLong()));
            m_avgLatency->setText(QString("%1 ms").arg(o.value("latency_avg").toDouble(), 0, 'f', 1));
            m_minLatency->setText("min " + QString::number(o.value("latency_min").toDouble(), 'f', 1) + " ms");
            m_maxLatency->setText("max " + QString::number(o.value("latency_max").toDouble(), 'f', 1) + " ms");
            m_errorsTotal->setText(QString::number(o.value("err_count_total").toVariant().toLongLong()));
            m_failedLogins->setText("failed admin logins 24h: "
                + QString::number(o.value("failed_admin_logins_24h").toInt()));
            m_coverCount->setText(QString::number(o.value("cover_count").toVariant().toLongLong()));
            m_coverBytes->setText("bytes " + humanBytes(o.value("cover_bytes").toVariant().toLongLong()));
            auto onionPct = o.value("onion_pct").toDouble();
            m_onionPct->setText(QString("%1%").arg(onionPct, 0, 'f', 1));
            m_clearPct->setText("clearnet " + QString::number(100.0 - onionPct, 'f', 1) + "%");
            emit countsUpdated(
                o.value("user_count").toInt(),
                o.value("device_count").toInt(),
                o.value("msgs_24h").toInt(),
                o.value("err_count_total").toInt());
        });
}
