#include "users_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QMenu>
#include <QInputDialog>
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
    m_table->setColumnCount(4);
    m_table->setHorizontalHeaderLabels({"Username", "Devices", "Created", "ID"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &UsersTab::refresh);
    connect(m_banBtn,     &QPushButton::clicked, this, &UsersTab::onBanSelected);
    connect(m_deleteBtn,  &QPushButton::clicked, this, &UsersTab::onDeleteSelected);
    // Double-click opens the user-detail dialog.
    connect(m_table, &QTableWidget::cellDoubleClicked,
            [this](int row, int) {
        if (row < 0) return;
        QString uname = m_table->item(row, 0)->text();
        QString uid   = m_table->item(row, 3)->text();
        emit openUserRequested(uid, uname);
    });

    // Right-click context menu on a user row — quickest path to a ban.
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableWidget::customContextMenuRequested,
            [this](const QPoint &pos) {
        auto *item = m_table->itemAt(pos);
        if (!item) return;
        QString username = m_table->item(item->row(), 0)->text();
        QMenu menu(this);
        auto *openAct   = menu.addAction("Open user details");
        menu.addSeparator();
        auto *banAct    = menu.addAction("Ban user (cascades HWIDs)…");
        auto *deleteAct = menu.addAction("Delete user…");
        auto *chosen    = menu.exec(m_table->viewport()->mapToGlobal(pos));
        if (chosen == openAct) {
            QString uid = m_table->item(item->row(), 3)->text();
            emit openUserRequested(uid, username);
            return;
        }
        if (chosen == banAct) {
            bool ok = false;
            QString reason = QInputDialog::getText(
                this, "Ban " + username,
                "Reason (optional) — shown to the user on their next login attempt:",
                QLineEdit::Normal, "", &ok);
            if (!ok) return;
            QJsonObject body;
            body["kind"]   = "username";
            body["value"]  = username;
            body["reason"] = reason;
            m_client->postJson("/api/v1/admin/bans", body,
                [this, username](const QJsonDocument &d, const QString &err) {
                    if (!err.isEmpty()) {
                        QMessageBox::warning(this, "Ban failed", err);
                        return;
                    }
                    int n = d.object().value("hwids_banned").toArray().size();
                    QMessageBox::information(this, "Banned",
                        QString("Banned %1 + %2 hardware ID(s).").arg(username).arg(n));
                });
            emit banUserRequested(username);  // also surface to BansTab
        } else if (chosen == deleteAct) {
            // Defer to existing button logic
            m_table->selectRow(item->row());
            onDeleteSelected();
        }
    });

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
    // Server returns shape: { users: [{username, user_id, created, devices}, …] }
    // via /admin/stats/users. There's no /admin/users GET — that path
    // 404s. /admin/users/{id}/details exists for the per-row drill-down
    // but isn't a listing.
    m_client->getJson("/api/v1/admin/stats/users",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) return;
            auto users = d.object().value("users").toArray();
            m_table->setRowCount(users.size());
            int r = 0;
            for (const auto &uv : users) {
                auto u = uv.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(u.value("username").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(QString::number(u.value("devices").toInt())));
                m_table->setItem(r, 2, new QTableWidgetItem(u.value("created").toString()));
                m_table->setItem(r, 3, new QTableWidgetItem(u.value("user_id").toString()));
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
        auto id = m_table->item(idx.row(), 3)->text();
        m_client->deleteRequest(QString("/api/v1/admin/users/%1").arg(id),
            [this](const QJsonDocument &, const QString &) { refresh(); });
    }
}
