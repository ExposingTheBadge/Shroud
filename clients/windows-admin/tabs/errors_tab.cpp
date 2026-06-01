#include "errors_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>

ErrorsTab::ErrorsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);
    auto *info = new QLabel(
        "Canonical SHROUD error catalog — the same registry the relay "
        "uses when raising HTTP errors. Quote a code (e.g. <b>EA002</b>) "
        "in a bug report and any operator can look up the exact failure "
        "mode without guessing.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *bar = new QHBoxLayout;
    m_search = new QLineEdit;
    m_search->setPlaceholderText("Filter by code / title / detail…");
    m_refreshBtn = new QPushButton("Refresh");
    m_count = new QLabel("—");
    m_count->setStyleSheet("color:#888;padding:0 10px");
    bar->addWidget(new QLabel("Search:"));
    bar->addWidget(m_search, 1);
    bar->addWidget(m_count);
    bar->addWidget(m_refreshBtn);
    l->addLayout(bar);

    m_table = new QTableWidget;
    m_table->setColumnCount(4);
    m_table->setHorizontalHeaderLabels({"Code", "HTTP", "Title", "Detail"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setWordWrap(true);
    m_table->verticalHeader()->setDefaultSectionSize(60);
    l->addWidget(m_table, 1);

    connect(m_refreshBtn, &QPushButton::clicked, this, &ErrorsTab::refresh);
    connect(m_search, &QLineEdit::textChanged, this, &ErrorsTab::applyFilter);
    refresh();
}

void ErrorsTab::refresh() {
    m_client->getJson("/api/v1/error-codes",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) {
                m_count->setText("load failed: " + err);
                return;
            }
            auto arr = d.object().value("errors").toArray();
            m_table->setRowCount(arr.size());
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(o.value("code").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(QString::number(o.value("http").toInt())));
                m_table->setItem(r, 2, new QTableWidgetItem(o.value("title").toString()));
                m_table->setItem(r, 3, new QTableWidgetItem(o.value("detail").toString()));
                r++;
            }
            m_table->resizeRowsToContents();
            m_count->setText(QString("%1 entries").arg(arr.size()));
        });
}

void ErrorsTab::applyFilter(const QString &needle) {
    for (int r = 0; r < m_table->rowCount(); ++r) {
        bool hit = needle.isEmpty();
        for (int c = 0; !hit && c < m_table->columnCount(); ++c) {
            auto *it = m_table->item(r, c);
            if (it && it->text().contains(needle, Qt::CaseInsensitive)) hit = true;
        }
        m_table->setRowHidden(r, !hit);
    }
}
