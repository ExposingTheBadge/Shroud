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

static QString humanUptime(qint64 s) {
    if (s <= 0) return "—";
    qint64 d = s / 86400, h = (s % 86400) / 3600, m = (s % 3600) / 60;
    if (d > 0) return QString("%1d %2h").arg(d).arg(h);
    if (h > 0) return QString("%1h %2m").arg(h).arg(m);
    return QString("%1m").arg(m);
}

FederationTab::FederationTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *root = new QVBoxLayout(this);
    auto *bar  = new QHBoxLayout;
    m_summary  = new QLabel("Polling…");
    m_summary->setStyleSheet("font-size:14px;font-weight:600");
    m_refreshBtn = new QPushButton("Refresh");
    bar->addWidget(m_summary, 1);
    bar->addWidget(m_refreshBtn);
    root->addLayout(bar);

    auto *gridContainer = new QFrame;
    m_grid = new QGridLayout(gridContainer);
    m_grid->setSpacing(8);
    root->addWidget(gridContainer, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &FederationTab::refresh);
    connect(&m_timer, &QTimer::timeout, this, &FederationTab::refresh);
    m_timer.start(10'000);

    refresh();
}

static QString safeStr(const QJsonValue &v) {
    return v.isString() ? v.toString() : v.toVariant().toString();
}

void FederationTab::refresh() {
    m_client->getJson("/api/v1/admin/federation",
        [this](const QJsonDocument &d, const QString &err) {
            // Clear existing grid
            while (auto *item = m_grid->takeAt(0)) {
                if (auto *w = item->widget()) w->deleteLater();
                delete item;
            }
            if (!err.isEmpty() || !d.isObject()) {
                m_summary->setText("Federation poll failed: " + err);
                return;
            }
            auto obj = d.object();
            auto summary = obj.value("summary").toObject();
            int reachable = summary.value("reachable").toInt();
            int total     = summary.value("total").toInt();
            m_summary->setText(QString("Federation: %1 / %2 reachable")
                                   .arg(reachable).arg(total));
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
                    auto *err = new QLabel("<span style='color:#ff7f7f'>"
                        + safeStr(r.value("error")).toHtmlEscaped() + "</span>");
                    err->setTextFormat(Qt::RichText);
                    err->setWordWrap(true);
                    cl->addWidget(err);
                }
                cl->addStretch();
                m_grid->addWidget(card, row, col);
                if (++col >= 3) { col = 0; ++row; }
            }
        });
}
