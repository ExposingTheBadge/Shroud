#include "stats_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QPlainTextEdit>
#include <QJsonDocument>

StatsTab::StatsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);
    m_dump = new QPlainTextEdit;
    m_dump->setReadOnly(true);
    m_dump->setStyleSheet("font-family:Consolas,monospace;font-size:11px");
    l->addWidget(m_dump);

    connect(&m_timer, &QTimer::timeout, this, &StatsTab::refresh);
    m_timer.start(8'000);
    refresh();
}

void StatsTab::refresh() {
    m_client->getJson("/api/v1/admin/stats/overview",
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) { m_dump->setPlainText("ERROR: " + err); return; }
            m_dump->setPlainText(QString::fromUtf8(d.toJson(QJsonDocument::Indented)));
        });
}
