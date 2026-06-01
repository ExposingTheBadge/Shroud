#include "diagnostics_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QProcess>
#include <QFileDialog>
#include <QDir>

DiagnosticsTab::DiagnosticsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Polls the anonymous-diagnostics inbox. The operator's private "
        "X25519 key NEVER leaves the operator's machine — this tab shells "
        "out to <code>python -m tools.diagnostics_inbox poll</code> using "
        "the configured keyfile, and displays the decrypted output.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *bar = new QHBoxLayout;
    m_keyfile = new QLineEdit;
    m_keyfile->setText(QDir::home().filePath(".config/shroud/diag.keypair.json"));
    m_pollBtn = new QPushButton("Poll inbox");
    auto *browseBtn = new QPushButton("…");
    bar->addWidget(new QLabel("Keyfile:"));
    bar->addWidget(m_keyfile, 1);
    bar->addWidget(browseBtn);
    bar->addWidget(m_pollBtn);
    l->addLayout(bar);

    m_output = new QPlainTextEdit;
    m_output->setReadOnly(true);
    m_output->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#e0e0e0");
    l->addWidget(m_output, 1);

    connect(browseBtn, &QPushButton::clicked, [this]() {
        auto p = QFileDialog::getOpenFileName(this, "diag keypair", m_keyfile->text());
        if (!p.isEmpty()) m_keyfile->setText(p);
    });
    connect(m_pollBtn, &QPushButton::clicked, this, &DiagnosticsTab::onPoll);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyReadStandardOutput, this, &DiagnosticsTab::onProcessOutput);
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this](int code, QProcess::ExitStatus) { onProcessFinished(code); });
}

void DiagnosticsTab::onPoll() {
    if (m_proc->state() != QProcess::NotRunning) return;
    m_output->appendPlainText("[poll] starting…");
    m_pollBtn->setEnabled(false);
    // Run from the repo root so `python -m tools.diagnostics_inbox` resolves.
    m_proc->setWorkingDirectory("D:/GHOSTLINK");
    QStringList args = {
        "-m", "tools.diagnostics_inbox", "poll",
        "--keyfile", m_keyfile->text(),
        "--relay-url", m_client->relayUrl(),
    };
    m_proc->start("python", args);
}

void DiagnosticsTab::onProcessOutput() {
    m_output->appendPlainText(QString::fromUtf8(m_proc->readAllStandardOutput()).trimmed());
}

void DiagnosticsTab::onProcessFinished(int code) {
    m_output->appendPlainText(QString("[poll] finished (exit %1)").arg(code));
    m_pollBtn->setEnabled(true);
}
