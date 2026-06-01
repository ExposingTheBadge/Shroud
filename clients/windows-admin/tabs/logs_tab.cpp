#include "logs_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>

LogsTab::LogsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *bar = new QHBoxLayout;
    m_filter = new QComboBox;
    m_filter->addItems({"all", "AUTH_FAIL", "BAN_BLOCK_AUTH", "BAN_BLOCK_REGISTER",
                        "AUDIT", "RECENT_ERROR", "ADMIN_SESSION", "FED_*"});
    m_search = new QLineEdit;
    m_search->setPlaceholderText("Filter substring…");
    m_connectBtn = new QPushButton("Connect WS");
    m_clearBtn   = new QPushButton("Clear");
    bar->addWidget(m_filter);
    bar->addWidget(m_search, 1);
    bar->addWidget(m_connectBtn);
    bar->addWidget(m_clearBtn);
    l->addLayout(bar);

    m_view = new QPlainTextEdit;
    m_view->setReadOnly(true);
    m_view->setMaximumBlockCount(5000);
    m_view->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#e0e0e0");
    l->addWidget(m_view, 1);

    connect(m_connectBtn, &QPushButton::clicked, this, &LogsTab::onConnect);
    connect(m_clearBtn,   &QPushButton::clicked, this, &LogsTab::onClear);
    connect(m_client, &AdminClient::wsEvent, this, &LogsTab::onEvent);
    connect(m_client, &AdminClient::wsConnected, [this]() {
        m_connected = true;
        m_connectBtn->setText("Disconnect WS");
        m_view->appendPlainText("[ws] connected");
    });
    connect(m_client, &AdminClient::wsDisconnected, [this]() {
        m_connected = false;
        m_connectBtn->setText("Connect WS");
        m_view->appendPlainText("[ws] disconnected");
    });
}

void LogsTab::onConnect() {
    if (m_connected) m_client->disconnectAdminWs();
    else             m_client->connectAdminWs();
}

void LogsTab::onClear() { m_view->clear(); }

void LogsTab::onEvent(const QJsonObject &ev) {
    QString type = ev.value("type").toString();
    QString filter = m_filter->currentText();
    if (filter != "all" && !type.contains(filter.section('*', 0, 0))) return;
    QString line = QString("[%1] %2 %3")
        .arg(QDateTime::currentDateTime().toString("HH:mm:ss"),
             type.leftJustified(20),
             QString::fromUtf8(QJsonDocument(ev).toJson(QJsonDocument::Compact)));
    QString needle = m_search->text();
    if (!needle.isEmpty() && !line.contains(needle, Qt::CaseInsensitive)) return;
    m_view->appendPlainText(line);
}
