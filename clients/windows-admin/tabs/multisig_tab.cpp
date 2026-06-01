#include "multisig_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QLabel>
#include <QComboBox>
#include <QProcess>
#include <QDir>

MultisigTab::MultisigTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Verify a GitHub release against the SHROUD <b>multisig roster</b>. "
        "Every release ships a manifest sealed by M-of-N independent signers "
        "(<code>release/signers.json</code>). This tab shells out to "
        "<code>python -m release.verify_release</code>, which pulls the "
        "manifest + signatures from the release page and checks the M-of-N "
        "threshold against the published Ed25519 roster.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *fl = new QFormLayout;
    m_repoBox = new QLineEdit("ExposingTheBadge/Shroud");
    m_tagBox = new QComboBox;
    m_tagBox->setEditable(true);
    m_tagBox->setPlaceholderText("Tag (e.g. v2.6.6)");
    m_loadBtn = new QPushButton("Load recent tags");
    m_verifyBtn = new QPushButton("Verify");
    m_verifyBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    auto *bar = new QHBoxLayout;
    bar->addWidget(m_tagBox, 2);
    bar->addWidget(m_loadBtn);
    bar->addWidget(m_verifyBtn);
    fl->addRow("Repo", m_repoBox);
    fl->addRow("Tag",  bar);
    l->addLayout(fl);

    m_status = new QLabel;
    m_status->setStyleSheet("padding:6px;color:#aaa");
    l->addWidget(m_status);

    m_output = new QPlainTextEdit;
    m_output->setReadOnly(true);
    m_output->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#cfcfcf");
    l->addWidget(m_output, 1);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyReadStandardOutput, this, &MultisigTab::onProcessOutput);
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this](int code, QProcess::ExitStatus) { onProcessFinished(code); });

    connect(m_loadBtn,   &QPushButton::clicked, this, &MultisigTab::onLoadReleases);
    connect(m_verifyBtn, &QPushButton::clicked, this, &MultisigTab::onVerifyTag);

    onLoadReleases();
}

void MultisigTab::onLoadReleases() {
    if (m_proc->state() != QProcess::NotRunning) return;
    m_status->setText("Pulling recent tags via gh…");
    m_proc->setWorkingDirectory(QDir::homePath());
    QStringList args = {
        "release", "list",
        "--repo", m_repoBox->text(),
        "--limit", "10",
        "--json", "tagName"
    };
    // We dispatch this through a separate runner so we don't tangle output
    // with the verify run.
    auto *one = new QProcess(this);
    one->setProcessChannelMode(QProcess::MergedChannels);
    connect(one, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this, one](int code, QProcess::ExitStatus) {
        QString text = QString::fromUtf8(one->readAllStandardOutput());
        one->deleteLater();
        if (code != 0) { m_status->setText("gh failed: " + text.left(200)); return; }
        // Cheap extraction — output is `[{"tagName":"v2.6.6"},...]`
        m_tagBox->clear();
        int from = 0;
        while (true) {
            int kw = text.indexOf("\"tagName\":\"", from);
            if (kw < 0) break;
            int s = kw + 11;
            int e = text.indexOf("\"", s);
            if (e < 0) break;
            m_tagBox->addItem(text.mid(s, e - s));
            from = e + 1;
        }
        if (m_tagBox->count() > 0) m_status->setText("Loaded " + QString::number(m_tagBox->count()) + " tag(s).");
    });
    one->start("gh", args);
}

void MultisigTab::onVerifyTag() {
    if (m_proc->state() != QProcess::NotRunning) return;
    QString tag = m_tagBox->currentText().trimmed();
    if (tag.isEmpty()) { m_status->setText("Pick a tag first."); return; }
    m_output->clear();
    m_status->setText("Verifying " + tag + "…");
    m_proc->setWorkingDirectory("D:/GHOSTLINK");
    QStringList args = {
        "-m", "release.verify_release",
        "--repo", m_repoBox->text(),
        "--tag",  tag,
    };
    m_proc->start("python", args);
}

void MultisigTab::onProcessOutput() {
    m_output->appendPlainText(QString::fromUtf8(m_proc->readAllStandardOutput()).trimmed());
}

void MultisigTab::onProcessFinished(int code) {
    m_output->appendPlainText(QString("\n[python] exit %1").arg(code));
    m_status->setText(code == 0 ? "Verification PASSED." : QString("Verification FAILED (%1).").arg(code));
}
