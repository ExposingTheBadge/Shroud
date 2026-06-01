#include "backup_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QPushButton>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProcess>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <QDir>
#include <QInputDialog>
#include <QJsonObject>
#include <QJsonArray>

BackupTab::BackupTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Operator-encrypted snapshots of the relay DB. Backups are "
        "Argon2id-key-derived AES-256-GCM, sealed with an operator "
        "passphrase that NEVER leaves the relay-admin machine. The relay "
        "only stores the ciphertext; restoring requires the passphrase "
        "that was used at backup time. Catalog at "
        "<code>/api/v1/admin/backups</code>.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *bar = new QHBoxLayout;
    m_takeBtn    = new QPushButton("Take backup now");
    m_takeBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 12px");
    m_dlBtn      = new QPushButton("Download selected");
    m_restoreBtn = new QPushButton("Restore selected");
    m_restoreBtn->setStyleSheet("background:#5a3a0a;color:white");
    m_delBtn     = new QPushButton("Delete selected");
    m_delBtn->setStyleSheet("background:#7a1a1a;color:white");
    m_refreshBtn = new QPushButton("Refresh");
    bar->addWidget(m_takeBtn);
    bar->addStretch();
    bar->addWidget(m_dlBtn);
    bar->addWidget(m_restoreBtn);
    bar->addWidget(m_delBtn);
    bar->addWidget(m_refreshBtn);
    l->addLayout(bar);

    m_status = new QLabel("Idle");
    m_status->setStyleSheet("color:#888;padding:4px");
    l->addWidget(m_status);

    m_table = new QTableWidget;
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({"ID", "Taken at", "Size", "Kind", "Note"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    l->addWidget(m_table, 1);

    m_log = new QPlainTextEdit;
    m_log->setReadOnly(true);
    m_log->setMaximumHeight(140);
    m_log->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#cfcfcf");
    l->addWidget(m_log);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyReadStandardOutput, this, &BackupTab::onProcessOutput);
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this](int code, QProcess::ExitStatus) { onProcessFinished(code); });

    connect(m_refreshBtn, &QPushButton::clicked, this, &BackupTab::refresh);
    connect(m_takeBtn,    &QPushButton::clicked, this, &BackupTab::onTakeBackup);
    connect(m_dlBtn,      &QPushButton::clicked, this, &BackupTab::onDownload);
    connect(m_restoreBtn, &QPushButton::clicked, this, &BackupTab::onRestore);
    connect(m_delBtn,     &QPushButton::clicked, this, &BackupTab::onDelete);

    refresh();
}

static QString humanBytes(qint64 b) {
    if (b < 1024) return QString::number(b) + " B";
    if (b < 1024 * 1024) return QString::number(b / 1024.0, 'f', 1) + " KB";
    if (b < 1024LL * 1024 * 1024) return QString::number(b / (1024.0 * 1024), 'f', 1) + " MB";
    return QString::number(b / (1024.0 * 1024 * 1024), 'f', 2) + " GB";
}

void BackupTab::refresh() {
    m_client->getJson("/api/v1/admin/backups",
        [this](const QJsonDocument &d, const QString &err) {
            m_table->setRowCount(0);
            if (!err.isEmpty()) { m_status->setText("load failed: " + err); return; }
            auto arr = d.object().value("backups").toArray();
            m_table->setRowCount(arr.size());
            int r = 0;
            for (const auto &v : arr) {
                auto o = v.toObject();
                m_table->setItem(r, 0, new QTableWidgetItem(o.value("id").toString()));
                m_table->setItem(r, 1, new QTableWidgetItem(o.value("taken_at").toString()));
                m_table->setItem(r, 2, new QTableWidgetItem(humanBytes(o.value("size_bytes").toVariant().toLongLong())));
                m_table->setItem(r, 3, new QTableWidgetItem(o.value("kind").toString()));
                m_table->setItem(r, 4, new QTableWidgetItem(o.value("note").toString()));
                r++;
            }
            m_status->setText(QString("%1 backups").arg(arr.size()));
        });
}

void BackupTab::onTakeBackup() {
    bool ok = false;
    QString note = QInputDialog::getText(this, "Take backup",
        "Optional note (visible in catalog only — not encrypted):",
        QLineEdit::Normal, "", &ok);
    if (!ok) return;
    QJsonObject body; body["note"] = note;
    m_status->setText("Taking backup…");
    m_client->postJson("/api/v1/admin/backups", body,
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) { m_status->setText("backup failed: " + err); return; }
            m_status->setText("backup id=" + d.object().value("id").toString());
            refresh();
        });
}

void BackupTab::onDownload() {
    auto sel = m_table->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    QString id = m_table->item(sel.first().row(), 0)->text();
    QString suggest = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
        + "/shroud-backup-" + id + ".bin";
    QString out = QFileDialog::getSaveFileName(this, "Save backup", suggest);
    if (out.isEmpty()) return;

    m_status->setText("Downloading…");
    // Defer to curl so we get a streaming download instead of buffering
    // the whole blob into a JSON envelope.
    QStringList args = {
        "-fsSL", "-k", "--max-time", "300",
        m_client->relayUrl() + "/api/v1/admin/backups/" + id + "/download",
        "-H", "Cookie: shroud_admin=" + m_client->adminSessionCookie(),
        "-o", out,
    };
    m_proc->start("curl", args);
}

void BackupTab::onRestore() {
    auto sel = m_table->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    QString id = m_table->item(sel.first().row(), 0)->text();
    bool ok = false;
    QString pw = QInputDialog::getText(this, "Restore",
        "Passphrase used when this backup was taken:",
        QLineEdit::Password, "", &ok);
    if (!ok || pw.isEmpty()) return;
    if (QMessageBox::warning(this, "Confirm restore",
        QString("Restore backup %1?\nThis OVERWRITES the current relay state. "
                "The current state is auto-snapshotted before restore so you "
                "can roll back, but unsaved in-memory state is lost.").arg(id),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
    QJsonObject body; body["passphrase"] = pw;
    m_status->setText("Restoring…");
    m_client->postJson(QString("/api/v1/admin/backups/%1/restore").arg(id), body,
        [this](const QJsonDocument &d, const QString &err) {
            if (!err.isEmpty()) { m_status->setText("restore failed: " + err); return; }
            m_status->setText("Restore submitted. Relay will restart.");
            m_log->appendPlainText(QString::fromUtf8(d.toJson(QJsonDocument::Indented)));
        });
}

void BackupTab::onDelete() {
    auto sel = m_table->selectionModel()->selectedRows();
    if (sel.isEmpty()) return;
    QString id = m_table->item(sel.first().row(), 0)->text();
    if (QMessageBox::warning(this, "Delete backup",
        QString("Delete backup %1? Cannot be recovered.").arg(id),
        QMessageBox::Yes | QMessageBox::No) != QMessageBox::Yes) return;
    m_client->deleteRequest(QString("/api/v1/admin/backups/%1").arg(id),
        [this](const QJsonDocument &, const QString &err) {
            if (!err.isEmpty()) { m_status->setText("delete failed: " + err); return; }
            refresh();
        });
}

void BackupTab::onProcessOutput() {
    m_log->appendPlainText(QString::fromUtf8(m_proc->readAllStandardOutput()).trimmed());
}

void BackupTab::onProcessFinished(int code) {
    m_log->appendPlainText(QString("[curl] exit %1").arg(code));
    m_status->setText(code == 0 ? "Download complete." : QString("Download failed (%1).").arg(code));
}
