#include "audit_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QDateTime>
#include <QJsonArray>
#include <QJsonObject>

AuditTab::AuditTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *bar = new QHBoxLayout;
    m_actionFilter = new QComboBox;
    m_actionFilter->addItems({"all", "AUTH_FAIL", "BAN_BLOCK_AUTH", "BAN_BLOCK_REGISTER",
                              "BAN_ADD", "BAN_REMOVE", "BAN_LIFT_USER",
                              "ADMIN_SESSION", "WIPE", "PANIC"});
    m_search = new QLineEdit;
    m_search->setPlaceholderText("Filter substring across all columns…");
    m_count  = new QLabel("—");
    m_count->setStyleSheet("color:#888;padding:0 10px");
    m_refreshBtn = new QPushButton("Refresh");
    bar->addWidget(new QLabel("Action:"));
    bar->addWidget(m_actionFilter);
    bar->addWidget(m_search, 1);
    bar->addWidget(m_count);
    bar->addWidget(m_refreshBtn);
    l->addLayout(bar);

    m_table = new QTableWidget;
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({"Time", "Actor", "Action", "Target", "Detail"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn,   &QPushButton::clicked, this, &AuditTab::refresh);
    connect(m_actionFilter, &QComboBox::currentTextChanged, this, &AuditTab::applyFilter);
    connect(m_search, &QLineEdit::textChanged, this, &AuditTab::applyFilter);
    // Live append from /ws/admin events whose type contains "AUDIT" or is one
    // of the BAN_* / AUTH_FAIL hooks the server publishes via publish_event.
    connect(m_client, &AdminClient::wsEvent, this, &AuditTab::onWsEvent);
    refresh();
}

void AuditTab::refresh() {
    m_client->getJson("/api/v1/admin/stats/audit",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) { m_count->setText("load failed: " + err); return; }
            auto arr = d.object().value("rows").toArray();
            m_table->setRowCount(arr.size());
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(o.value("at").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(o.value("actor").toString()));
                m_table->setItem(r, 2, new QTableWidgetItem(o.value("action").toString()));
                m_table->setItem(r, 3, new QTableWidgetItem(o.value("target").toString()));
                m_table->setItem(r, 4, new QTableWidgetItem(o.value("detail").toString()));
                r++;
            }
            m_count->setText(QString("%1 rows").arg(arr.size()));
            applyFilter();
        });
}

void AuditTab::onWsEvent(const QJsonObject &ev) {
    // Server publishes events shaped { type, actor?, action?, target?, detail?, at? }.
    // We append anything that looks like an audit-relevant row to the top.
    QString type = ev.value("type").toString();
    static const QStringList interesting = {
        "AUDIT", "AUTH_FAIL", "BAN_ADD", "BAN_REMOVE", "BAN_BLOCK_AUTH",
        "BAN_BLOCK_REGISTER", "BAN_LIFT_USER", "WIPE", "PANIC", "ADMIN_SESSION",
    };
    bool match = false;
    for (const auto &t : interesting) {
        if (type == t || type.contains(t, Qt::CaseInsensitive)) { match = true; break; }
    }
    if (!match) return;
    m_table->insertRow(0);
    m_table->setItem(0, 0, new QTableWidgetItem(
        ev.value("at").toString(QDateTime::currentDateTime().toString(Qt::ISODate))));
    m_table->setItem(0, 1, new QTableWidgetItem(ev.value("actor").toString()));
    m_table->setItem(0, 2, new QTableWidgetItem(type));
    m_table->setItem(0, 3, new QTableWidgetItem(ev.value("target").toString()));
    m_table->setItem(0, 4, new QTableWidgetItem(ev.value("detail").toString()));
    // Cap at 2000 rows so a flood doesn't blow memory.
    if (m_table->rowCount() > 2000) m_table->removeRow(m_table->rowCount() - 1);
    m_count->setText(QString("%1 rows").arg(m_table->rowCount()));
    applyFilter();
}

void AuditTab::applyFilter() {
    QString needle = m_search->text();
    QString actionPick = m_actionFilter->currentText();
    int visible = 0;
    for (int r = 0; r < m_table->rowCount(); ++r) {
        QString action = m_table->item(r, 2) ? m_table->item(r, 2)->text() : "";
        bool actionHit = (actionPick == "all") || action.contains(actionPick, Qt::CaseInsensitive);
        bool needleHit = needle.isEmpty();
        for (int c = 0; !needleHit && c < m_table->columnCount(); ++c) {
            auto *it = m_table->item(r, c);
            if (it && it->text().contains(needle, Qt::CaseInsensitive)) needleHit = true;
        }
        bool hide = !(actionHit && needleHit);
        m_table->setRowHidden(r, hide);
        if (!hide) visible++;
    }
    m_count->setText(QString("%1 / %2 rows").arg(visible).arg(m_table->rowCount()));
}
