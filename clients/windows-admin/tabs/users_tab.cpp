#include "users_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QHeaderView>

UsersTab::UsersTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);
    auto *bar = new QHBoxLayout;
    m_search = new QLineEdit;
    m_search->setPlaceholderText("Filter…");
    m_refreshBtn = new QPushButton("Refresh");
    m_banBtn     = new QPushButton("Ban selected");
    m_banBtn->setStyleSheet("background:#b00020;color:white");
    m_deleteBtn  = new QPushButton("Delete selected");
    m_deleteBtn->setStyleSheet("background:#7a1a1a;color:white");
    bar->addWidget(m_search, 1);
    bar->addWidget(m_refreshBtn);
    bar->addWidget(m_banBtn);
    bar->addWidget(m_deleteBtn);
    l->addLayout(bar);

    m_table = new QTableWidget;
    m_table->setColumnCount(6);
    m_table->setHorizontalHeaderLabels({"Username", "Tier", "Devices", "Created", "Last seen", "ID"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &UsersTab::refresh);
    connect(m_banBtn,     &QPushButton::clicked, this, &UsersTab::onBanSelected);
    connect(m_deleteBtn,  &QPushButton::clicked, this, &UsersTab::onDeleteSelected);
    connect(m_search, &QLineEdit::textChanged, [this](const QString &s) {
        for (int r = 0; r < m_table->rowCount(); ++r) {
            bool hit = s.isEmpty();
            for (int c = 0; !hit && c < m_table->columnCount(); ++c) {
                auto *it = m_table->item(r, c);
                if (it && it->text().contains(s, Qt::CaseInsensitive)) hit = true;
            }
            m_table->setRowHidden(r, !hit);
        }
    });

    refresh();
}

void UsersTab::refresh() {
    m_client->getJson("/api/v1/admin/users",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) return;
            auto users = d.object().value("users").toArray();
            m_table->setRowCount(users.size());
            int r = 0;
            for (const auto &uv : users) {
                auto u = uv.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(u.value("username").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(u.value("tier").toString()));
                m_table->setItem(r, 2, new QTableWidgetItem(QString::number(u.value("device_count").toInt())));
                m_table->setItem(r, 3, new QTableWidgetItem(u.value("created_at").toString()));
                m_table->setItem(r, 4, new QTableWidgetItem(u.value("last_seen").toString()));
                m_table->setItem(r, 5, new QTableWidgetItem(u.value("id").toString()));
                r++;
            }
        });
}

void UsersTab::onBanSelected() {
    auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    QStringList names;
    for (const auto &idx : rows) names << m_table->item(idx.row(), 0)->text();
    if (QMessageBox::warning(this, "Ban users",
        "Ban these users? Their hardware IDs will also be banned:\n" + names.join("\n"),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    for (const auto &n : names) emit banUserRequested(n);
}

void UsersTab::onDeleteSelected() {
    auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    if (QMessageBox::warning(this, "Delete users",
        QString("Delete %1 user(s) and all their data? This cannot be undone.").arg(rows.size()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    for (const auto &idx : rows) {
        auto id = m_table->item(idx.row(), 5)->text();
        m_client->deleteRequest(QString("/api/v1/admin/users/%1").arg(id),
            [this](const QJsonDocument &, const QString &) { refresh(); });
    }
}
