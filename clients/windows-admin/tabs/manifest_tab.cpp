#include "manifest_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QProcess>
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QLabel>
#include <QJsonDocument>

ManifestTab::ManifestTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Build + sign the operator manifest. Shells out to "
        "<code>python -m tools.build_operator_manifest build</code>. "
        "The manifest-signing private key never leaves the operator's machine.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *fl = new QFormLayout;
    m_keyfile     = new QLineEdit(QDir::home().filePath(".config/shroud/manifest.ed25519.json"));
    m_homeRelay   = new QLineEdit(m_client->relayUrl());
    m_diagPub     = new QLineEdit("7191a786437e38ebe616b9508b3110afb1a635e08ac034a330093acca708fd54");
    m_stickerCdn  = new QLineEdit("https://stickers.shroud.example/");
    m_ttlDays     = new QLineEdit("30");
    m_outPath     = new QLineEdit(QDir::home().filePath(".config/shroud/operator_manifest.signed.json"));
    fl->addRow("Signing keyfile",     m_keyfile);
    fl->addRow("Home relay URL",      m_homeRelay);
    fl->addRow("Diagnostics pubkey",  m_diagPub);
    fl->addRow("Stickers CDN",        m_stickerCdn);
    fl->addRow("TTL days",            m_ttlDays);
    fl->addRow("Output path",         m_outPath);
    l->addLayout(fl);

    auto *bar = new QHBoxLayout;
    m_buildBtn = new QPushButton("Build + sign");
    m_viewBtn  = new QPushButton("View current manifest");
    bar->addWidget(m_buildBtn);
    bar->addWidget(m_viewBtn);
    bar->addStretch();
    l->addLayout(bar);

    m_output = new QPlainTextEdit;
    m_output->setReadOnly(true);
    m_output->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#e0e0e0");
    l->addWidget(m_output, 1);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyReadStandardOutput, this, &ManifestTab::onProcessOutput);
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this](int code, QProcess::ExitStatus) { onProcessFinished(code); });
    connect(m_buildBtn, &QPushButton::clicked, this, &ManifestTab::onBuild);
    connect(m_viewBtn,  &QPushButton::clicked, this, &ManifestTab::onView);
}

void ManifestTab::onBuild() {
    if (m_proc->state() != QProcess::NotRunning) return;
    m_buildBtn->setEnabled(false);
    m_output->appendPlainText("[build] starting…");
    m_proc->setWorkingDirectory("D:/GHOSTLINK");
    QStringList args = {
        "-m", "tools.build_operator_manifest", "build",
        "--keyfile",      m_keyfile->text(),
        "--home-relay",   m_homeRelay->text(),
        "--diag-pubkey",  m_diagPub->text(),
        "--stickers-cdn", m_stickerCdn->text(),
        "--ttl-days",     m_ttlDays->text(),
        "--out",          m_outPath->text(),
    };
    m_proc->start("python", args);
}

void ManifestTab::onView() {
    QFile f(m_outPath->text());
    if (!f.open(QIODevice::ReadOnly)) {
        m_output->appendPlainText("[view] could not open: " + m_outPath->text());
        return;
    }
    auto doc = QJsonDocument::fromJson(f.readAll());
    m_output->setPlainText(QString::fromUtf8(doc.toJson(QJsonDocument::Indented)));
}

void ManifestTab::onProcessOutput() {
    m_output->appendPlainText(QString::fromUtf8(m_proc->readAllStandardOutput()).trimmed());
}

void ManifestTab::onProcessFinished(int code) {
    m_output->appendPlainText(QString("[build] finished (exit %1)").arg(code));
    m_buildBtn->setEnabled(true);
}
