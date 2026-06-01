#include "user_detail_dialog.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLabel>
#include <QTextBrowser>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QPushButton>
#include <QMessageBox>
#include <QInputDialog>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>

UserDetailDialog::UserDetailDialog(AdminClient *client, const QString &userId,
                                   const QString &username, QWidget *parent)
    : QDialog(parent), m_client(client), m_userId(userId), m_username(username) {
    setWindowTitle("User: " + username);
    resize(900, 620);

    auto *l = new QVBoxLayout(this);
    m_title = new QLabel(QString("<b>%1</b>  <span style='color:#888'>%2</span>")
        .arg(username, userId.left(16)));
    m_title->setStyleSheet("font-size:14px;padding:6px");
    m_title->setTextFormat(Qt::RichText);
    l->addWidget(m_title);

    m_meta = new QLabel("loading…");
    m_meta->setStyleSheet("color:#aaa;font-family:Consolas,monospace;padding:0 6px");
    m_meta->setWordWrap(true);
    l->addWidget(m_meta);

    auto *bar = new QHBoxLayout;
    m_banBtn = new QPushButton("Ban user (cascades HWIDs)…");
    m_banBtn->setStyleSheet("background:#b00020;color:white");
    m_delBtn = new QPushButton("Delete user");
    m_delBtn->setStyleSheet("background:#7a1a1a;color:white");
    m_refreshBtn = new QPushButton("Refresh");
    m_closeBtn   = new QPushButton("Close");
    bar->addWidget(m_banBtn);
    bar->addWidget(m_delBtn);
    bar->addStretch();
    bar->addWidget(m_refreshBtn);
    bar->addWidget(m_closeBtn);
    l->addLayout(bar);

    auto *devLbl = new QLabel("Devices");
    devLbl->setStyleSheet("color:#888;font-size:10px;text-transform:uppercase;padding-top:8px");
    l->addWidget(devLbl);
    m_deviceTable = new QTableWidget;
    m_deviceTable->setColumnCount(5);
    m_deviceTable->setHorizontalHeaderLabels({"Device ID", "Platform", "Device Name", "HWID", "Last Seen"});
    m_deviceTable->horizontalHeader()->setStretchLastSection(true);
    m_deviceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_deviceTable->setMaximumHeight(220);
    l->addWidget(m_deviceTable);

    auto *rawLbl = new QLabel("Raw record");
    rawLbl->setStyleSheet("color:#888;font-size:10px;text-transform:uppercase;padding-top:8px");
    l->addWidget(rawLbl);
    m_raw = new QTextBrowser;
    m_raw->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#cfcfcf");
    l->addWidget(m_raw, 1);

    connect(m_closeBtn,   &QPushButton::clicked, this, &QDialog::close);
    connect(m_refreshBtn, &QPushButton::clicked, this, &UserDetailDialog::refresh);
    connect(m_banBtn,     &QPushButton::clicked, this, &UserDetailDialog::onBan);
    connect(m_delBtn,     &QPushButton::clicked, this, &UserDetailDialog::onDelete);

    refresh();
}

void UserDetailDialog::refresh() {
    m_client->getJson(QString("/api/v1/admin/users/%1").arg(m_userId),
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) {
                m_meta->setText("load failed: " + err);
                return;
            }
            auto u = d.object().value("user").toObject();
            QString tier = u.value("tier").toString();
            QString created = u.value("created_at").toString();
            int devs = u.value("device_count").toInt();
            m_meta->setText(QString("tier %1 · devices %2 · created %3")
                .arg(tier).arg(devs).arg(created));
            m_raw->setPlainText(QString::fromUtf8(QJsonDocument(u).toJson(QJsonDocument::Indented)));
        });

    m_client->getJson("/api/v1/admin/devices",
        [this](const QJsonDocument &d, const QString &) {
            m_deviceTable->setRowCount(0);
            auto arr = d.object().value("devices").toArray();
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                if (o.value("user_id").toString() != m_userId) continue;
                m_deviceTable->insertRow(r);
                m_deviceTable->setItem(r, 0, new QTableWidgetItem(o.value("id").toString()));
                m_deviceTable->setItem(r, 1, new QTableWidgetItem(o.value("platform").toString()));
                m_deviceTable->setItem(r, 2, new QTableWidgetItem(o.value("device_name").toString()));
                m_deviceTable->setItem(r, 3, new QTableWidgetItem(o.value("hwid").toString()));
                m_deviceTable->setItem(r, 4, new QTableWidgetItem(o.value("last_seen").toString()));
                r++;
            }
        });
}

void UserDetailDialog::onBan() {
    bool ok = false;
    QString reason = QInputDialog::getText(this, "Ban " + m_username,
        "Reason (optional, shown to the user on their next login attempt):",
        QLineEdit::Normal, "", &ok);
    if (!ok) return;
    QJsonObject body;
    body["kind"]   = "username";
    body["value"]  = m_username;
    body["reason"] = reason;
    m_client->postJson("/api/v1/admin/bans", body,
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) { QMessageBox::warning(this, "Ban failed", err); return; }
            int n = d.object().value("hwids_banned").toArray().size();
            QMessageBox::information(this, "Banned",
                QString("Banned %1 + %2 hardware ID(s).").arg(m_username).arg(n));
            emit banUserRequested(m_username);
        });
}

void UserDetailDialog::onDelete() {
    if (QMessageBox::warning(this, "Delete user",
        QString("Delete user '%1' and all their data? This cannot be undone.").arg(m_username),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    m_client->deleteRequest(QString("/api/v1/admin/users/%1").arg(m_userId),
        [this](const QJsonDocument &, const QString &err) {
            if (!err.isEmpty()) { QMessageBox::warning(this, "Delete failed", err); return; }
            QMessageBox::information(this, "Deleted", "User removed.");
            accept();
        });
}
