#include "devices_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QLineEdit>
#include <QPushButton>
#include <QMenu>
#include <QLabel>
#include <QMessageBox>
#include <QGuiApplication>
#include <QClipboard>
#include <QJsonArray>
#include <QJsonObject>

DevicesTab::DevicesTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *bar = new QHBoxLayout;
    m_search = new QLineEdit;
    m_search->setPlaceholderText("Filter device id / user / hwid / platform…");
    m_count  = new QLabel("—");
    m_count->setStyleSheet("color:#888;padding:0 10px");
    m_refreshBtn = new QPushButton("Refresh");
    m_killBtn    = new QPushButton("Kill selected");
    m_killBtn->setStyleSheet("background:#7a1a1a;color:white");
    bar->addWidget(m_search, 1);
    bar->addWidget(m_count);
    bar->addWidget(m_refreshBtn);
    bar->addWidget(m_killBtn);
    l->addLayout(bar);

    m_table = new QTableWidget;
    m_table->setColumnCount(6);
    m_table->setHorizontalHeaderLabels({"Device ID", "User", "Platform", "HWID", "Last seen", "Created"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &DevicesTab::refresh);
    connect(m_killBtn,    &QPushButton::clicked, this, &DevicesTab::onKillSelected);
    connect(m_search, &QLineEdit::textChanged, this, &DevicesTab::applyFilter);
    connect(m_table, &QTableWidget::customContextMenuRequested,
            [this](const QPoint &pos) {
        auto *it = m_table->itemAt(pos);
        if (!it) return;
        int row = it->row();
        QString did   = m_table->item(row, 0)->text();
        QString user  = m_table->item(row, 1)->text();
        QString hwid  = m_table->item(row, 3)->text();
        QMenu menu(this);
        auto *copyId   = menu.addAction("Copy device ID");
        auto *copyHwid = menu.addAction("Copy HWID");
        menu.addSeparator();
        auto *banHwAct = menu.addAction("Ban this hardware ID");
        auto *killAct  = menu.addAction("Kill device");
        auto *chosen   = menu.exec(m_table->viewport()->mapToGlobal(pos));
        if (chosen == copyId)   QGuiApplication::clipboard()->setText(did);
        else if (chosen == copyHwid) QGuiApplication::clipboard()->setText(hwid);
        else if (chosen == banHwAct && !hwid.isEmpty()) emit banHwidRequested(hwid);
        else if (chosen == killAct) {
            if (QMessageBox::warning(this, "Kill device",
                QString("Drop device row %1 (user %2)?").arg(did.left(16), user),
                QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                m_client->deleteRequest(QString("/api/v1/admin/devices/%1").arg(did),
                    [this](const QJsonDocument &, const QString &) { refresh(); });
            }
        }
    });

    refresh();
}

void DevicesTab::refresh() {
    m_client->getJson("/api/v1/admin/devices",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) { m_count->setText("load failed: " + err); return; }
            auto arr = d.object().value("devices").toArray();
            m_table->setRowCount(arr.size());
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(o.value("id").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(o.value("username").toString()));
                m_table->setItem(r, 2, new QTableWidgetItem(o.value("platform").toString()));
                m_table->setItem(r, 3, new QTableWidgetItem(o.value("hwid").toString()));
                m_table->setItem(r, 4, new QTableWidgetItem(o.value("last_seen").toString()));
                m_table->setItem(r, 5, new QTableWidgetItem(o.value("created").toString()));
                r++;
            }
            m_count->setText(QString("%1 devices").arg(arr.size()));
        });
}

void DevicesTab::onKillSelected() {
    auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    if (QMessageBox::warning(this, "Kill devices",
        QString("Drop %1 device row(s)?").arg(rows.size()),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    for (const auto &idx : rows) {
        QString did = m_table->item(idx.row(), 0)->text();
        m_client->deleteRequest(QString("/api/v1/admin/devices/%1").arg(did),
            [this](const QJsonDocument &, const QString &) { refresh(); });
    }
}

void DevicesTab::applyFilter(const QString &needle) {
    for (int r = 0; r < m_table->rowCount(); ++r) {
        bool hit = needle.isEmpty();
        for (int c = 0; !hit && c < m_table->columnCount(); ++c) {
            auto *it = m_table->item(r, c);
            if (it && it->text().contains(needle, Qt::CaseInsensitive)) hit = true;
        }
        m_table->setRowHidden(r, !hit);
    }
}
