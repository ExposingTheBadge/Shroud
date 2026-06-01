#include "bans_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFormLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QMessageBox>
#include <QJsonArray>
#include <QJsonObject>
#include <QHeaderView>

BansTab::BansTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "<b>Banning a username cascades to every hardware ID</b> we have seen on devices "
        "linked to that user. Re-creating an account from the same hardware will be blocked. "
        "HWID and IP bans can also be added directly.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *form = new QGroupBox("Add ban");
    auto *fl = new QFormLayout(form);
    m_kindBox = new QComboBox;
    m_kindBox->addItems({"username", "hwid", "ip"});
    m_inputValue  = new QLineEdit;  m_inputValue->setPlaceholderText("username | hwid hex | IP address");
    m_inputReason = new QLineEdit;  m_inputReason->setPlaceholderText("Reason (visible in audit log)");
    fl->addRow("Kind", m_kindBox);
    fl->addRow("Value", m_inputValue);
    fl->addRow("Reason", m_inputReason);
    m_addBtn = new QPushButton("Add ban (cascades HWIDs for username kind)");
    m_addBtn->setStyleSheet("background:#b00020;color:white;padding:6px");
    fl->addRow(m_addBtn);
    l->addWidget(form);

    auto *bar = new QHBoxLayout;
    m_refreshBtn = new QPushButton("Refresh");
    m_liftBtn    = new QPushButton("Lift selected row");
    m_liftUserBtn = new QPushButton("Lift entire user cascade");
    bar->addWidget(m_refreshBtn);
    bar->addStretch();
    bar->addWidget(m_liftBtn);
    bar->addWidget(m_liftUserBtn);
    l->addLayout(bar);

    m_table = new QTableWidget;
    m_table->setColumnCount(7);
    m_table->setHorizontalHeaderLabels({"id", "kind", "value", "reason", "by", "at", "origin"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &BansTab::refresh);
    connect(m_addBtn,     &QPushButton::clicked, this, &BansTab::onAddBan);
    connect(m_liftBtn,    &QPushButton::clicked, this, &BansTab::onLiftSelected);
    connect(m_liftUserBtn,&QPushButton::clicked, this, &BansTab::onLiftUserCascade);

    refresh();
}

void BansTab::prefillUsername(const QString &username) {
    m_kindBox->setCurrentText("username");
    m_inputValue->setText(username);
    m_inputReason->setFocus();
}

void BansTab::refresh() {
    m_client->getJson("/api/v1/admin/bans",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) return;
            auto arr = d.object().value("bans").toArray();
            m_table->setRowCount(arr.size());
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(QString::number(o.value("id").toInt())));
                m_table->setItem(r, 1, new QTableWidgetItem(o.value("kind").toString()));
                m_table->setItem(r, 2, new QTableWidgetItem(o.value("value").toString()));
                m_table->setItem(r, 3, new QTableWidgetItem(o.value("reason").toString()));
                m_table->setItem(r, 4, new QTableWidgetItem(o.value("banned_by").toString()));
                m_table->setItem(r, 5, new QTableWidgetItem(o.value("banned_at").toString()));
                m_table->setItem(r, 6, new QTableWidgetItem(o.value("origin_user").toString()));
                r++;
            }
        });
}

void BansTab::onAddBan() {
    QJsonObject body;
    body["kind"]   = m_kindBox->currentText();
    body["value"]  = m_inputValue->text().trimmed();
    body["reason"] = m_inputReason->text().trimmed();
    if (body["value"].toString().isEmpty()) return;
    if (QMessageBox::warning(this, "Confirm",
        QString("Add %1 ban for: %2").arg(body["kind"].toString(), body["value"].toString()),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;

    m_client->postJson("/api/v1/admin/bans", body,
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                QMessageBox::warning(this, "Ban failed", err);
            } else {
                auto o = d.object();
                int hwids = o.value("hwids_banned").toArray().size();
                if (o.value("kind").toString() == "username") {
                    QMessageBox::information(this, "Ban added",
                        QString("Banned %1 + %2 hardware ID(s)").arg(
                            o.value("username").toString()).arg(hwids));
                }
            }
            m_inputValue->clear();
            m_inputReason->clear();
            refresh();
        });
}

void BansTab::onLiftSelected() {
    auto rows = m_table->selectionModel()->selectedRows();
    for (const auto &idx : rows) {
        QString id = m_table->item(idx.row(), 0)->text();
        m_client->deleteRequest(QString("/api/v1/admin/bans/%1").arg(id),
            [this](const QJsonDocument &, const QString &) { refresh(); });
    }
}

void BansTab::onLiftUserCascade() {
    auto rows = m_table->selectionModel()->selectedRows();
    if (rows.isEmpty()) return;
    QString username = m_table->item(rows[0].row(), 6)->text();
    if (username.isEmpty()) username = m_table->item(rows[0].row(), 2)->text();
    if (QMessageBox::warning(this, "Lift cascade",
        QString("Remove EVERY ban row tied to user '%1' (including all HWID rows)?")
            .arg(username),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    QJsonObject body; body["username"] = username;
    m_client->postJson("/api/v1/admin/bans/lift-user", body,
        [this](const QJsonDocument &, const QString &) { refresh(); });
}
