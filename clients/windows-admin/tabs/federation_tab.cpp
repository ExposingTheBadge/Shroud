#include "federation_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QFrame>
#include <QJsonArray>
#include <QJsonObject>
#include <QGuiApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QScrollArea>

static QString humanUptime(qint64 s) {
    if (s <= 0) return "—";
    qint64 d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
    if (d > 0) return QString("%1d %2h").arg(d).arg(h);
    if (h > 0) return QString("%1h %2m").arg(h).arg(m);
    return QString("%1m").arg(m);
}

FederationTab::FederationTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *outer = new QVBoxLayout(this);

    // -- Top bar ------------------------------------------------------
    auto *bar  = new QHBoxLayout;
    m_summary  = new QLabel("Polling…");
    m_summary->setStyleSheet("font-size:14px;font-weight:600");
    m_refreshBtn = new QPushButton("Refresh");
    auto *syncBtn = new QPushButton("Sync state now");
    syncBtn->setStyleSheet("background:#2e7d32;color:white;padding:4px 10px");
    bar->addWidget(m_summary, 1);
    bar->addWidget(syncBtn);
    bar->addWidget(m_refreshBtn);
    outer->addLayout(bar);

    connect(syncBtn, &QPushButton::clicked, [this]() {
        m_summary->setText("Triggering state-event sync from every peer…");
        m_client->postJson("/api/v1/admin/federation/sync-now", QJsonObject(),
            [this](const QJsonDocument &d, const QString &err) {
                if (!err.isEmpty()) {
                    m_summary->setText("Sync failed: " + err);
                    return;
                }
                int total = 0;
                for (const auto &p : d.object().value("peers").toArray()) {
                    total += p.toObject().value("applied").toInt();
                }
                m_summary->setText(
                    QString("Applied %1 new state event(s) — refresh in 1s.")
                        .arg(total));
                QTimer::singleShot(1000, this, &FederationTab::refresh);
            });
    });

    // -- Scrollable body ---------------------------------------------
    auto *scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    auto *bodyWidget = new QWidget;
    auto *bodyLayout = new QVBoxLayout(bodyWidget);
    bodyLayout->setSpacing(14);

    // Relay cards
    auto *relaysHeader = new QLabel("<b>Federation peers</b>");
    relaysHeader->setStyleSheet("font-size:13px;color:#cfd8dc");
    bodyLayout->addWidget(relaysHeader);
    auto *gridContainer = new QFrame;
    m_grid = new QGridLayout(gridContainer);
    m_grid->setSpacing(8);
    bodyLayout->addWidget(gridContainer);

    // AWS assets
    auto *awsHeaderRow = new QHBoxLayout;
    auto *awsHeader = new QLabel("<b>AWS assets</b>");
    awsHeader->setStyleSheet("font-size:13px;color:#cfd8dc");
    m_awsSummary = new QLabel("—");
    m_awsSummary->setStyleSheet("color:#90caf9;font-family:Consolas,monospace");
    awsHeaderRow->addWidget(awsHeader);
    awsHeaderRow->addSpacing(8);
    awsHeaderRow->addWidget(m_awsSummary);
    awsHeaderRow->addStretch();
    bodyLayout->addLayout(awsHeaderRow);

    auto *awsContainer = new QFrame;
    m_awsLayout = new QVBoxLayout(awsContainer);
    m_awsLayout->setSpacing(8);
    bodyLayout->addWidget(awsContainer);

    bodyLayout->addStretch();
    scroll->setWidget(bodyWidget);
    outer->addWidget(scroll, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &FederationTab::refresh);
    connect(&m_timer, &QTimer::timeout, this, &FederationTab::refresh);
    m_timer.start(10'000);

    refresh();
}

static QString safeStr(const QJsonValue &v) {
    return v.isString() ? v.toString() : v.toVariant().toString();
}

static QColor stateColor(const QString &st) {
    if (st == "running") return QColor("#66bb6a");
    if (st == "stopped") return QColor("#9e9e9e");
    if (st == "pending" || st == "stopping" || st == "shutting-down"
        || st == "rebooting")
        return QColor("#ffb74d");
    return QColor("#ef5350");
}

void FederationTab::runInstanceAction(const QString &action,
                                      const QString &instanceId,
                                      const QString &region,
                                      const QString &name)
{
    QString verb = action == "start" ? "Start"
                 : action == "stop"  ? "Stop"
                                     : "Reboot";
    auto reply = QMessageBox::question(
        this, verb + " EC2 instance?",
        QString("%1 %2 (%3) in %4?")
            .arg(verb, name.isEmpty() ? "this instance" : name,
                 instanceId, region),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (reply != QMessageBox::Yes) return;

    QJsonObject body;
    body["action"]      = action;
    body["instance_id"] = instanceId;
    body["region"]      = region;
    m_summary->setText(QString("Sending %1 to %2 …").arg(action, instanceId));
    m_client->postJson("/api/v1/admin/aws/instance/action", body,
        [this, action, instanceId](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                m_summary->setText(QString("%1 failed: %2").arg(action, err));
                QMessageBox::warning(this, "AWS action failed", err);
                return;
            }
            auto o = d.object();
            m_summary->setText(QString("%1 %2: %3 → %4")
                .arg(action, instanceId,
                     safeStr(o.value("prev_state")),
                     safeStr(o.value("curr_state"))));
            QTimer::singleShot(2000, this, &FederationTab::refresh);
        });
}

void FederationTab::refresh() {
    m_client->getJson("/api/v1/admin/federation",
        [this](const QJsonDocument &d, const QString &err) {
            // --- Reset relay grid -----------------------------------
            while (auto *item = m_grid->takeAt(0)) {
                if (auto *w = item->widget()) w->deleteLater();
                delete item;
            }
            // --- Reset AWS section ----------------------------------
            while (auto *item = m_awsLayout->takeAt(0)) {
                if (auto *w = item->widget()) w->deleteLater();
                if (auto *l = item->layout()) {
                    while (auto *c = l->takeAt(0)) {
                        if (auto *cw = c->widget()) cw->deleteLater();
                        delete c;
                    }
                    delete l;
                }
                delete item;
            }

            if (!err.isEmpty() || !d.isObject()) {
                m_summary->setText("Federation poll failed: " + err);
                m_awsSummary->setText("—");
                return;
            }
            auto obj = d.object();
            auto summary = obj.value("summary").toObject();
            int reachable = summary.value("reachable").toInt();
            int total     = summary.value("total").toInt();
            m_summary->setText(QString("Federation: %1 / %2 reachable")
                                   .arg(reachable).arg(total));

            // --- Relay cards ----------------------------------------
            int col = 0, row = 0;
            for (const auto &rv : obj.value("relays").toArray()) {
                auto r = rv.toObject();
                auto stats = r.value("stats").toObject();
                auto tor   = stats.value("tor").toObject();
                auto traf  = stats.value("traffic").toObject();
                auto fed   = stats.value("federation").toObject();
                auto cap   = stats.value("capacity").toObject();
                bool ok = r.value("reachable").toBool();

                auto *card = new QFrame;
                card->setFrameShape(QFrame::StyledPanel);
                card->setMinimumSize(280, 180);
                card->setStyleSheet(QString(
                    "QFrame { background:%1; border:1px solid %2; border-radius:4px; padding:8px; }"
                ).arg(ok ? "#1a2a1a" : "#2a1a1a", ok ? "#2e7d32" : "#b00020"));
                auto *cl = new QVBoxLayout(card);
                cl->setSpacing(2);

                auto *hdr = new QLabel(QString("<b>%1</b> <span style='color:%2'>%3</span>")
                    .arg(safeStr(r.value("endpoint")),
                         ok ? "#7fff7f" : "#ff7f7f",
                         ok ? "OK" : "DOWN"));
                hdr->setTextFormat(Qt::RichText);
                cl->addWidget(hdr);
                cl->addWidget(new QLabel("<span style='color:#888'>"
                    + safeStr(r.value("operator")).toHtmlEscaped()
                    + "</span>"));
                if (ok) {
                    cl->addWidget(new QLabel(QString("v%1 %2")
                        .arg(safeStr(stats.value("version")),
                             safeStr(stats.value("git_sha")))));
                    cl->addWidget(new QLabel("uptime: " + humanUptime(
                        stats.value("uptime_seconds").toVariant().toLongLong())));
                    cl->addWidget(new QLabel(QString("federation peers: %1")
                        .arg(fed.value("active_peers").toInt())));
                    cl->addWidget(new QLabel(QString("reqs: %1   errs: %2")
                        .arg(traf.value("requests_total").toVariant().toLongLong())
                        .arg(traf.value("errors_total").toVariant().toLongLong())));
                    cl->addWidget(new QLabel(QString("anon pending: %1   diag: %2")
                        .arg(traf.value("anon_messages_pending").toVariant().toLongLong())
                        .arg(traf.value("diag_reports_pending").toVariant().toLongLong())));
                    cl->addWidget(new QLabel(QString("disk: %1%   load: %2")
                        .arg(cap.value("disk_used_pct").toDouble(), 0, 'f', 1)
                        .arg(QString("%1 %2 %3")
                            .arg(cap.value("load_avg").toArray().at(0).toDouble(), 0, 'f', 2)
                            .arg(cap.value("load_avg").toArray().at(1).toDouble(), 0, 'f', 2)
                            .arg(cap.value("load_avg").toArray().at(2).toDouble(), 0, 'f', 2))));
                    auto onion = safeStr(tor.value("onion_address"));
                    auto *tl = new QLabel(QString("tor: <span style='color:%1'>%2</span>")
                        .arg(onion.isEmpty() ? "#888" : "#ffb74d",
                             onion.isEmpty() ? "disabled" : onion.toHtmlEscaped()));
                    tl->setTextFormat(Qt::RichText);
                    tl->setWordWrap(true);
                    cl->addWidget(tl);
                } else {
                    auto *errLbl = new QLabel("<span style='color:#ff7f7f'>"
                        + safeStr(r.value("error")).toHtmlEscaped() + "</span>");
                    errLbl->setTextFormat(Qt::RichText);
                    errLbl->setWordWrap(true);
                    cl->addWidget(errLbl);
                }
                if (ok && safeStr(r.value("endpoint")) != "self") {
                    auto *abar = new QHBoxLayout;
                    auto *copyBtn   = new QPushButton("Copy URL");
                    auto *manifestBtn = new QPushButton("Fetch manifest");
                    abar->addWidget(copyBtn);
                    abar->addWidget(manifestBtn);
                    abar->addStretch();
                    cl->addLayout(abar);
                    QString endpoint = safeStr(r.value("endpoint"));
                    connect(copyBtn, &QPushButton::clicked, [endpoint]() {
                        QGuiApplication::clipboard()->setText(endpoint);
                    });
                    connect(manifestBtn, &QPushButton::clicked, [this, endpoint]() {
                        auto previousUrl = m_client->relayUrl();
                        m_client->setRelayUrl(endpoint);
                        m_client->getJson("/api/v1/operator-manifest",
                            [this, previousUrl](const QJsonDocument &d, const QString &err) {
                                m_client->setRelayUrl(previousUrl);
                                if (!err.isEmpty()) {
                                    m_summary->setText("Manifest fetch failed: " + err);
                                    return;
                                }
                                m_summary->setText("Manifest OK — schema "
                                    + d.object().value("schema").toString()
                                    + ", peers "
                                    + QString::number(d.object().value("federation_peers").toArray().size()));
                            });
                    });
                }
                cl->addStretch();
                m_grid->addWidget(card, row, col);
                if (++col >= 3) { col = 0; ++row; }
            }

            // --- AWS section ----------------------------------------
            auto aws = obj.value("aws").toObject();
            bool awsOk = aws.value("available").toBool();
            if (!awsOk) {
                m_awsSummary->setText("unavailable");
                m_awsSummary->setStyleSheet("color:#ef5350;font-family:Consolas,monospace");
                auto *errLbl = new QLabel(
                    QString("<span style='color:#ef5350'>%1</span>")
                        .arg(safeStr(aws.value("error")).toHtmlEscaped()));
                errLbl->setTextFormat(Qt::RichText);
                errLbl->setWordWrap(true);
                m_awsLayout->addWidget(errLbl);
                auto *hint = new QLabel(
                    "<span style='color:#888;font-size:11px'>"
                    "Attach an IAM instance role with <code>ec2:DescribeInstances</code>, "
                    "<code>ec2:DescribeRegions</code>, <code>ec2:StartInstances</code>, "
                    "<code>ec2:StopInstances</code>, <code>ec2:RebootInstances</code> "
                    "to the relay's EC2 instance, then <code>pip install boto3</code> on the relay."
                    "</span>");
                hint->setTextFormat(Qt::RichText);
                hint->setWordWrap(true);
                m_awsLayout->addWidget(hint);
                return;
            }
            auto awsSum = aws.value("summary").toObject();
            int running = awsSum.value("running").toInt();
            int stopped = awsSum.value("stopped").toInt();
            int totalI  = awsSum.value("total").toInt();
            int other   = awsSum.value("other").toInt();
            m_awsSummary->setStyleSheet("color:#90caf9;font-family:Consolas,monospace");
            m_awsSummary->setText(QString("%1 running · %2 stopped · %3 other · %4 total")
                                      .arg(running).arg(stopped).arg(other).arg(totalI));

            auto regions = aws.value("regions").toObject();
            QStringList regionNames = regions.keys();
            regionNames.sort();
            if (regionNames.isEmpty()) {
                auto *empty = new QLabel(
                    "<span style='color:#888'>No EC2 instances found.</span>");
                empty->setTextFormat(Qt::RichText);
                m_awsLayout->addWidget(empty);
                return;
            }

            for (const auto &rg : regionNames) {
                auto rgObj = regions.value(rg).toObject();
                auto items = rgObj.value("instances").toArray();
                auto *frame = new QFrame;
                frame->setFrameShape(QFrame::StyledPanel);
                frame->setStyleSheet(
                    "QFrame { background:#13181f; border:1px solid #263238; "
                    "border-radius:4px; padding:6px; }");
                auto *fl = new QVBoxLayout(frame);
                fl->setSpacing(4);
                auto *rgLbl = new QLabel(QString(
                    "<span style='color:#90caf9;font-weight:700;letter-spacing:1px'>%1</span>"
                    "&nbsp;&nbsp;<span style='color:#888;font-size:11px'>%2 instance(s)</span>")
                    .arg(rg.toUpper()).arg(items.size()));
                rgLbl->setTextFormat(Qt::RichText);
                fl->addWidget(rgLbl);

                auto *tbl = new QTableWidget(items.size(), 7, frame);
                tbl->setHorizontalHeaderLabels(
                    {"Name", "Instance ID", "State", "Type",
                     "Public IP", "AZ", "Actions"});
                tbl->verticalHeader()->setVisible(false);
                tbl->setEditTriggers(QAbstractItemView::NoEditTriggers);
                tbl->setSelectionMode(QAbstractItemView::NoSelection);
                tbl->setShowGrid(false);
                tbl->setAlternatingRowColors(true);
                tbl->setStyleSheet(
                    "QTableWidget { background:#0d1117; color:#cfd8dc; "
                    "font-family:Consolas,monospace; font-size:11px; }"
                    "QHeaderView::section { background:#1c2330; color:#90caf9; "
                    "padding:4px; border:0px; }"
                    "QTableWidget::item { padding:3px 6px; }");
                tbl->horizontalHeader()->setSectionResizeMode(
                    QHeaderView::ResizeToContents);
                tbl->horizontalHeader()->setStretchLastSection(true);

                for (int i = 0; i < items.size(); ++i) {
                    auto inst = items.at(i).toObject();
                    QString name    = safeStr(inst.value("name"));
                    QString id      = safeStr(inst.value("id"));
                    QString state   = safeStr(inst.value("state"));
                    QString type    = safeStr(inst.value("type"));
                    QString pub     = safeStr(inst.value("pub_ip"));
                    QString az      = safeStr(inst.value("az"));
                    bool    isSelf  = inst.value("is_self").toBool();

                    auto *nameItem = new QTableWidgetItem(
                        isSelf ? (name.isEmpty() ? "this relay"
                                                 : name + "  (this relay)")
                               : (name.isEmpty() ? "—" : name));
                    if (isSelf) nameItem->setForeground(QBrush(QColor("#90caf9")));
                    tbl->setItem(i, 0, nameItem);
                    tbl->setItem(i, 1, new QTableWidgetItem(id));
                    auto *stItem = new QTableWidgetItem(state);
                    stItem->setForeground(QBrush(stateColor(state)));
                    QFont stf = stItem->font(); stf.setBold(true);
                    stItem->setFont(stf);
                    tbl->setItem(i, 2, stItem);
                    tbl->setItem(i, 3, new QTableWidgetItem(type));
                    tbl->setItem(i, 4, new QTableWidgetItem(pub.isEmpty() ? "—" : pub));
                    tbl->setItem(i, 5, new QTableWidgetItem(az));

                    auto *cell = new QWidget;
                    auto *cellL = new QHBoxLayout(cell);
                    cellL->setContentsMargins(2, 0, 2, 0);
                    cellL->setSpacing(4);
                    auto *startBtn  = new QPushButton("Start");
                    auto *stopBtn   = new QPushButton("Stop");
                    auto *rebootBtn = new QPushButton("Reboot");
                    // Rule 0: never offer to take down the box we're
                    // talking to. The server hard-refuses it anyway;
                    // this keeps the button from lying about it.
                    startBtn->setEnabled(state == "stopped");
                    stopBtn->setEnabled(state == "running" && !isSelf);
                    rebootBtn->setEnabled(state == "running" && !isSelf);
                    if (isSelf) {
                        stopBtn->setToolTip("This is the relay serving the "
                                            "admin panel — stop it from "
                                            "another relay or the AWS console.");
                        rebootBtn->setToolTip(stopBtn->toolTip());
                    }
                    startBtn->setStyleSheet("background:#2e7d32;color:white;padding:2px 8px");
                    stopBtn->setStyleSheet("background:#c62828;color:white;padding:2px 8px");
                    rebootBtn->setStyleSheet("background:#ef6c00;color:white;padding:2px 8px");
                    cellL->addWidget(startBtn);
                    cellL->addWidget(stopBtn);
                    cellL->addWidget(rebootBtn);
                    cellL->addStretch();
                    tbl->setCellWidget(i, 6, cell);

                    connect(startBtn,  &QPushButton::clicked,
                        [this, id, rg, name]() { runInstanceAction("start",  id, rg, name); });
                    connect(stopBtn,   &QPushButton::clicked,
                        [this, id, rg, name]() { runInstanceAction("stop",   id, rg, name); });
                    connect(rebootBtn, &QPushButton::clicked,
                        [this, id, rg, name]() { runInstanceAction("reboot", id, rg, name); });
                }
                int rowH = tbl->verticalHeader()->defaultSectionSize();
                int hdrH = tbl->horizontalHeader()->height();
                tbl->setFixedHeight(rowH * items.size() + hdrH + 4);
                fl->addWidget(tbl);

                QString rgErr = rgObj.value("error").toString();
                if (!rgErr.isEmpty()) {
                    auto *e = new QLabel("<span style='color:#ef5350'>"
                        + rgErr.toHtmlEscaped() + "</span>");
                    e->setTextFormat(Qt::RichText);
                    fl->addWidget(e);
                }
                m_awsLayout->addWidget(frame);
            }
        });
}
