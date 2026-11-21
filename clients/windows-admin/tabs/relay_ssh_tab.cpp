#include "relay_ssh_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFormLayout>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QProcess>
#include <QFileDialog>
#include <QFileInfo>
#include <QSettings>
#include <QApplication>

namespace {
constexpr const char *kDefaultHost = "173.245.244.180";

struct Preset { const char *label; const char *cmd; };
// Linux relay host commands. On a Windows relay host use the custom box.
const Preset PRESETS[] = {
    {"git pull",              "cd /opt/shroud/src && sudo git pull --ff-only"},
    {"Restart relay",         "sudo systemctl restart shroud-relay.service && sudo systemctl is-active shroud-relay.service"},
    {"Relay status",          "sudo systemctl status shroud-relay.service --no-pager -n 5"},
    {"Tor status",            "sudo systemctl is-active tor && cat /opt/shroud/data/onion_hostname.txt 2>/dev/null || echo '(no onion hostname)'"},
    {"Disk usage",            "df -h / /opt/shroud 2>/dev/null"},
    {"Tail journal (40)",     "sudo journalctl -u shroud-relay.service -n 40 --no-pager"},
};
}

RelaySshTab::RelaySshTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Run maintenance commands on the relay host over SSH. Set the host, "
        "user and private key once; they are remembered on this PC. The "
        "host key is pinned on first connect (accept-new).");
    info->setWordWrap(true);
    info->setStyleSheet("padding:8px;color:#c9d1d9;background:#161b22;"
                        "border-left:3px solid #7c5cff;border-radius:4px");
    l->addWidget(info);

    QSettings st;
    auto *form = new QFormLayout;
    m_hostEdit = new QLineEdit(st.value("ssh/host", kDefaultHost).toString());
    m_userEdit = new QLineEdit(st.value("ssh/user", "shroud").toString());
    m_keyEdit  = new QLineEdit(st.value("ssh/key").toString());
    m_keyEdit->setPlaceholderText("Path to the SSH private key (optional if ssh-agent has it)");
    auto *keyRow = new QHBoxLayout;
    auto *browse = new QPushButton("Browse…");
    keyRow->addWidget(m_keyEdit, 1);
    keyRow->addWidget(browse);
    form->addRow("Host", m_hostEdit);
    form->addRow("User", m_userEdit);
    form->addRow("Key", keyRow);
    l->addLayout(form);
    connect(browse, &QPushButton::clicked, this, &RelaySshTab::browseKey);
    for (auto *e : {m_hostEdit, m_userEdit, m_keyEdit})
        connect(e, &QLineEdit::editingFinished, this, &RelaySshTab::saveTarget);

    auto *grid = new QGridLayout;
    int i = 0;
    for (const auto &p : PRESETS) {
        auto *b = new QPushButton(p.label);
        b->setMinimumHeight(34);
        const QString cmd = p.cmd, lbl = p.label;
        connect(b, &QPushButton::clicked, this, [this, cmd, lbl]() { run(cmd, lbl); });
        grid->addWidget(b, i / 3, i % 3);
        ++i;
    }
    l->addLayout(grid);

    auto *cbar = new QHBoxLayout;
    m_customCmd = new QLineEdit;
    m_customCmd->setPlaceholderText("Custom command…");
    m_customRunBtn = new QPushButton("Run");
    cbar->addWidget(m_customCmd, 1);
    cbar->addWidget(m_customRunBtn);
    l->addLayout(cbar);
    connect(m_customRunBtn, &QPushButton::clicked, this, &RelaySshTab::runCustom);
    connect(m_customCmd, &QLineEdit::returnPressed, this, &RelaySshTab::runCustom);

    m_output = new QPlainTextEdit;
    m_output->setReadOnly(true);
    m_output->setStyleSheet("font-family:Consolas,monospace;font-size:11px;"
                            "background:#0d1117;color:#e6edf3");
    l->addWidget(m_output, 1);
}

void RelaySshTab::browseKey() {
    QString f = QFileDialog::getOpenFileName(this, "SSH private key", m_keyEdit->text());
    if (!f.isEmpty()) { m_keyEdit->setText(f); saveTarget(); }
}

void RelaySshTab::saveTarget() {
    QSettings st;
    st.setValue("ssh/host", m_hostEdit->text().trimmed());
    st.setValue("ssh/user", m_userEdit->text().trimmed());
    st.setValue("ssh/key",  m_keyEdit->text().trimmed());
}

void RelaySshTab::runCustom() {
    QString cmd = m_customCmd->text().trimmed();
    if (!cmd.isEmpty()) run(cmd, "custom");
}

void RelaySshTab::run(const QString &cmd, const QString &label) {
    const QString host = m_hostEdit->text().trimmed();
    const QString user = m_userEdit->text().trimmed();
    const QString key  = m_keyEdit->text().trimmed();
    if (host.isEmpty() || user.isEmpty()) {
        m_output->appendPlainText("[error] set a host and user first");
        return;
    }
    m_output->appendPlainText(QString("\n=== %1@%2 — %3 ===").arg(user, host, label));
    QStringList args = {"-o", "StrictHostKeyChecking=accept-new",
                        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                        "-o", "LogLevel=ERROR"};
    if (!key.isEmpty()) {
        if (!QFileInfo::exists(key)) {
            m_output->appendPlainText("[error] key file not found: " + key);
            return;
        }
        args << "-i" << key;
    }
    args << QString("%1@%2").arg(user, host) << cmd;

    // Asynchronous: the old tab blocked the whole window for up to a
    // minute per relay while ssh ran.
    auto *p = new QProcess(this);
    p->setProcessChannelMode(QProcess::MergedChannels);
    connect(p, &QProcess::readyReadStandardOutput, this, [this, p]() {
        m_output->appendPlainText(QString::fromUtf8(p->readAllStandardOutput()).trimmed());
    });
    connect(p, &QProcess::finished, this, [this, p](int code, QProcess::ExitStatus) {
        m_output->appendPlainText(QString("[exit %1]").arg(code));
        p->deleteLater();
    });
    connect(p, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart)
            m_output->appendPlainText("[error] could not start ssh; is OpenSSH installed?");
    });
    p->start("ssh", args);
}
