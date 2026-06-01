#include "relay_ssh_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QProcess>
#include <QDir>
#include <QFileInfo>

struct RelayDef {
    QString label;
    QString key;
    QString ip;
};

static const RelayDef RELAYS[] = {
    {"us-east-1", "shroud-relay.pem",         "44.202.225.57"},
    {"us-east-2", "shroud-relay-useast2.pem", "3.142.185.104"},
    {"us-west-2", "shroud-relay-uswest2.pem", "54.214.75.14"},
    {"eu-west-1", "shroud-relay-euwest1.pem", "54.171.165.223"},
};
static const int RELAY_COUNT = sizeof(RELAYS) / sizeof(RELAYS[0]);

RelaySshTab::RelaySshTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Run shell commands across the production relays. Uses each "
        "region's SSH key from <code>~/Documents/AWS-Keys/</code>. "
        "Target dropdown picks 'all' to fan out, or a single region.");
    info->setWordWrap(true);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *bar = new QHBoxLayout;
    m_targetBox = new QComboBox;
    m_targetBox->addItem("all");
    for (int i = 0; i < RELAY_COUNT; ++i) m_targetBox->addItem(RELAYS[i].label);
    bar->addWidget(new QLabel("Target:"));
    bar->addWidget(m_targetBox);
    bar->addStretch();
    l->addLayout(bar);

    auto *grid = new QGridLayout;
    int r = 0;
    auto addBtn = [&](QPushButton *&out, const QString &lbl, const QString &cmd) {
        out = new QPushButton(lbl);
        out->setMinimumHeight(36);
        connect(out, &QPushButton::clicked, [this, cmd, lbl]() { runOnAll(cmd, lbl); });
        grid->addWidget(out, r / 3, r % 3); r++;
    };
    addBtn(m_pullBtn,      "git pull origin master",
           "cd /opt/shroud/src && sudo git pull origin master");
    addBtn(m_restartBtn,   "Restart relay service",
           "sudo systemctl restart shroud-relay.service && sudo systemctl is-active shroud-relay.service");
    addBtn(m_torStatusBtn, "Tor status",
           "sudo systemctl is-active tor && cat /opt/shroud/data/onion_hostname.txt 2>/dev/null || echo '(no hostname file)'");
    addBtn(m_vacuumBtn,    "VACUUM DB",
           "sudo sqlite3 /opt/shroud/data/shroud.db 'VACUUM;' && echo VACUUM done");
    addBtn(m_journalBtn,   "Tail relay journal (20)",
           "sudo journalctl -u shroud-relay.service -n 20 --no-pager");
    l->addLayout(grid);

    auto *cbar = new QHBoxLayout;
    m_customCmd = new QLineEdit;
    m_customCmd->setPlaceholderText("Custom command (runs via sudo bash -c)…");
    m_customRunBtn = new QPushButton("Run");
    cbar->addWidget(m_customCmd, 1);
    cbar->addWidget(m_customRunBtn);
    l->addLayout(cbar);
    connect(m_customRunBtn, &QPushButton::clicked, this, &RelaySshTab::runCustom);

    m_output = new QPlainTextEdit;
    m_output->setReadOnly(true);
    m_output->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#e0e0e0");
    l->addWidget(m_output, 1);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_proc, &QProcess::readyReadStandardOutput, this, &RelaySshTab::onOutput);
}

void RelaySshTab::runCustom() {
    QString cmd = m_customCmd->text();
    if (cmd.isEmpty()) return;
    runOnAll(cmd, "custom");
}

void RelaySshTab::runOnAll(const QString &cmd, const QString &label) {
    QString target = m_targetBox->currentText();
    QString keyDir = QDir::home().filePath("Documents/AWS-Keys");
    for (int i = 0; i < RELAY_COUNT; ++i) {
        if (target != "all" && target != RELAYS[i].label) continue;
        QString keyfile = keyDir + "/" + RELAYS[i].key;
        m_output->appendPlainText(QString("\n=== %1 (%2) — %3 ===")
            .arg(RELAYS[i].label, RELAYS[i].ip, label));
        if (!QFileInfo(keyfile).exists()) {
            m_output->appendPlainText("[skip] SSH key missing: " + keyfile);
            continue;
        }
        QStringList args = {
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-i", keyfile,
            QString("ec2-user@%1").arg(RELAYS[i].ip),
            cmd,
        };
        QProcess p;
        p.setProcessChannelMode(QProcess::MergedChannels);
        p.start("ssh", args);
        if (!p.waitForFinished(60000)) {
            m_output->appendPlainText("[timeout]");
            p.kill();
            continue;
        }
        m_output->appendPlainText(QString::fromUtf8(p.readAllStandardOutput()).trimmed());
    }
}

void RelaySshTab::onOutput() {
    m_output->appendPlainText(QString::fromUtf8(m_proc->readAllStandardOutput()).trimmed());
}
