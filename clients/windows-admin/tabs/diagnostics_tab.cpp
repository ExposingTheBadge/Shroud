#include "diagnostics_tab.h"
#include "../admin_client.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QTextBrowser>
#include <QProcess>
#include <QFileDialog>
#include <QDir>
#include <QFileInfo>
#include <QStandardPaths>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>

DiagnosticsTab::DiagnosticsTab(AdminClient *client, QWidget *parent)
    : QWidget(parent), m_client(client) {
    auto *l = new QVBoxLayout(this);

    auto *info = new QLabel(
        "Drains the anonymous-diagnostics inbox on the currently-configured "
        "relay. The operator's X25519 private key NEVER leaves your machine "
        "— this tab spawns <code>python -m tools.diagnostics_inbox poll --json</code> "
        "with your local keyfile, parses the decoded payload, and renders one "
        "row per report. Reports are Rule-3 scrubbed before sealing, so "
        "messages and stack traces contain placeholders like &lt;UUID&gt;, "
        "&lt;EMAIL&gt;, &lt;IPV4&gt; instead of raw PII.");
    info->setWordWrap(true);
    info->setTextFormat(Qt::RichText);
    info->setStyleSheet("padding:6px;color:#bbb;background:#222;border-left:3px solid #ffb74d");
    l->addWidget(info);

    auto *bar = new QHBoxLayout;
    m_keyfile = new QLineEdit;
    m_keyfile->setText(QDir::home().filePath(".config/shroud/diag.keypair.json"));
    m_browseBtn = new QPushButton("…");
    m_pollBtn = new QPushButton("Poll inbox");
    m_pollBtn->setStyleSheet("background:#2e7d32;color:white;padding:6px 14px");
    bar->addWidget(new QLabel("Keyfile:"));
    bar->addWidget(m_keyfile, 1);
    bar->addWidget(m_browseBtn);
    bar->addWidget(m_pollBtn);
    l->addLayout(bar);

    m_status = new QLabel("Idle. Click 'Poll inbox' to fetch any pending reports.");
    m_status->setStyleSheet("color:#888;padding:4px");
    l->addWidget(m_status);

    m_table = new QTableWidget;
    m_table->setColumnCount(5);
    m_table->setHorizontalHeaderLabels({"Time", "App", "Version", "Kind", "Message"});
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setMaximumHeight(240);
    l->addWidget(m_table);

    m_detail = new QTextBrowser;
    m_detail->setStyleSheet("font-family:Consolas,monospace;font-size:11px;background:#0a0a0a;color:#cfcfcf");
    m_detail->setPlaceholderText("Select a row to see the full decoded report (stack + context).");
    l->addWidget(m_detail, 1);

    connect(m_browseBtn, &QPushButton::clicked, [this]() {
        auto p = QFileDialog::getOpenFileName(this, "diag keypair", m_keyfile->text());
        if (!p.isEmpty()) m_keyfile->setText(p);
    });
    connect(m_pollBtn, &QPushButton::clicked, this, &DiagnosticsTab::onPoll);
    connect(m_table, &QTableWidget::itemSelectionChanged,
            this, &DiagnosticsTab::onSelectionChanged);

    m_proc = new QProcess(this);
    m_proc->setProcessChannelMode(QProcess::SeparateChannels);
    connect(m_proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this](int code, QProcess::ExitStatus) { onProcessFinished(code); });

    // Auto-poll once on construction if the default keyfile exists, so
    // the operator opens the tab and sees rows immediately.
    if (QFileInfo(m_keyfile->text()).exists()) {
        QTimer::singleShot(0, this, &DiagnosticsTab::onPoll);
    }
}

QString DiagnosticsTab::resolvePython() const {
    // Try PATH first; on Windows 'py' is a stable launcher.
    QString p = QStandardPaths::findExecutable("python");
    if (p.isEmpty()) p = QStandardPaths::findExecutable("py");
    if (p.isEmpty()) p = QStandardPaths::findExecutable("python3");
    if (!p.isEmpty()) return p;
    // Common Windows install paths
    QStringList cands = {
        "C:/Program Files/Python312/python.exe",
        "C:/Program Files/Python311/python.exe",
        "C:/Program Files/Python310/python.exe",
        QDir::homePath() + "/AppData/Local/Programs/Python/Python312/python.exe",
        QDir::homePath() + "/AppData/Local/Programs/Python/Python311/python.exe",
    };
    for (const auto &c : cands) if (QFileInfo(c).exists()) return c;
    return QString();
}

void DiagnosticsTab::onPoll() {
    if (m_proc->state() != QProcess::NotRunning) return;
    if (!QFileInfo(m_keyfile->text()).exists()) {
        m_status->setText("Keyfile not found: " + m_keyfile->text());
        return;
    }
    QString py = resolvePython();
    if (py.isEmpty()) {
        m_status->setText("python not found on PATH — set %PATH% or install Python 3.10+.");
        return;
    }
    m_status->setText("Polling " + m_client->relayUrl() + "…");
    m_pollBtn->setEnabled(false);
    m_table->setRowCount(0);
    m_detail->clear();
    m_reports = QJsonArray();
    m_proc->setWorkingDirectory("D:/GHOSTLINK");
    QStringList args = {
        "-m", "tools.diagnostics_inbox", "poll",
        "--keyfile",   m_keyfile->text(),
        "--relay-url", m_client->relayUrl(),
        "--json",
    };
    m_proc->start(py, args);
}

void DiagnosticsTab::onProcessFinished(int code) {
    m_pollBtn->setEnabled(true);
    QByteArray out = m_proc->readAllStandardOutput();
    QByteArray err = m_proc->readAllStandardError();
    if (code != 0) {
        m_status->setText(QString("Poll failed (exit %1): %2")
            .arg(code).arg(QString::fromUtf8(err.left(300))));
        return;
    }
    QJsonParseError pe;
    QJsonDocument d = QJsonDocument::fromJson(out, &pe);
    if (pe.error != QJsonParseError::NoError) {
        m_status->setText("Could not parse poll output: " + pe.errorString());
        m_detail->setPlainText(QString::fromUtf8(out));
        return;
    }
    auto root = d.object();
    int scanned = root.value("tags_scanned").toInt();
    m_reports = root.value("reports").toArray();
    m_status->setText(QString("Scanned %1 tag(s) → %2 report(s)")
        .arg(scanned).arg(m_reports.size()));

    m_table->setRowCount(m_reports.size());
    int r = 0;
    for (const auto &rv : m_reports) {
        auto o = rv.toObject();
        auto dec = o.value("decoded").toObject();
        m_table->setItem(r, 0, new QTableWidgetItem(o.value("ts").toString()));
        m_table->setItem(r, 1, new QTableWidgetItem(dec.value("app").toString()));
        m_table->setItem(r, 2, new QTableWidgetItem(dec.value("app_version").toString()));
        m_table->setItem(r, 3, new QTableWidgetItem(dec.value("kind").toString()));
        QString msg = dec.value("message").toString();
        if (msg.length() > 200) msg = msg.left(200) + "…";
        m_table->setItem(r, 4, new QTableWidgetItem(msg));
        r++;
    }
    if (m_reports.size() > 0) m_table->selectRow(0);
}

void DiagnosticsTab::onSelectionChanged() {
    auto sel = m_table->selectionModel()->selectedRows();
    if (sel.isEmpty()) { m_detail->clear(); return; }
    int row = sel.first().row();
    if (row < 0 || row >= m_reports.size()) return;
    auto o = m_reports[row].toObject();
    auto dec = o.value("decoded").toObject();
    QString id = o.value("id").toString();
    QString ts = o.value("ts").toString();
    if (dec.isEmpty()) {
        m_detail->setPlainText(QString("id=%1 ts=%2\nDECRYPT FAILED: %3")
            .arg(id, ts, o.value("error").toString()));
        return;
    }
    QString html;
    html += QString("<b>id</b>           %1<br>").arg(id.toHtmlEscaped());
    html += QString("<b>ts</b>           %1<br>").arg(ts.toHtmlEscaped());
    html += QString("<b>app</b>          %1 v%2<br>")
        .arg(dec.value("app").toString().toHtmlEscaped(),
             dec.value("app_version").toString().toHtmlEscaped());
    html += QString("<b>os</b>           %1<br>").arg(dec.value("os").toString().toHtmlEscaped());
    html += QString("<b>kind</b>         %1<br>").arg(dec.value("kind").toString().toHtmlEscaped());
    html += QString("<b>message</b>      %1<br>").arg(dec.value("message").toString().toHtmlEscaped());
    QString stack = dec.value("stack").toString();
    if (!stack.isEmpty()) {
        html += "<br><b>stack</b><br><pre style='color:#e0e0e0;white-space:pre-wrap'>"
             + stack.toHtmlEscaped() + "</pre>";
    }
    auto ctx = dec.value("context").toObject();
    if (!ctx.isEmpty()) {
        html += "<br><b>context</b><br><pre style='color:#cfcfcf;white-space:pre-wrap'>";
        for (auto it = ctx.begin(); it != ctx.end(); ++it) {
            html += it.key().toHtmlEscaped() + " = "
                 + it.value().toVariant().toString().toHtmlEscaped() + "\n";
        }
        html += "</pre>";
    }
    m_detail->setHtml(html);
}
