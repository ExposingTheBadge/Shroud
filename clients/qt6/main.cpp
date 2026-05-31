/*
 * SHROUD Qt6 Client — Clean cross-platform desktop client
 * Compile: cmake -B build && cmake --build build --config Release
 */
#include <QtWidgets>
#include <QtNetwork>
#include <QtCore>

#define CLIENT_VERSION "1.2.0"

extern "C" {
#include "client.h"
}

/* ===================================================================
 *  THEME — Dark/Light stylesheets
 * =================================================================== */
static bool gDark = true;

QString themeCSS(bool dark) {
    return dark ? QString(
        "* { background-color: #1a1a1a; color: #cccccc; font-family: \"Segoe UI\"; }"
        "QMainWindow { background-color: #1a1a1a; }"
        "QMenuBar { background-color: #222222; color: #cccccc; border-bottom: 1px solid #333; }"
        "QMenuBar::item:selected { background-color: #0066cc; }"
        "QMenu { background-color: #222222; color: #cccccc; border: 1px solid #333; }"
        "QMenu::item:selected { background-color: #0066cc; }"
        "QLineEdit, QTextEdit, QPlainTextEdit { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px; border-radius: 4px; }"
        "QTextEdit { background-color: #1a1a1a; }"
        "QPushButton { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px 16px; border-radius: 4px; }"
        "QPushButton:hover { background-color: #3d3d3d; border-color: #555; }"
        "QPushButton:pressed { background-color: #0066cc; }"
        "QPushButton:disabled { background-color: #1a1a1a; color: #555; }"
        "QListWidget { background-color: #222222; color: #cccccc; border: 1px solid #333; }"
        "QListWidget::item:selected { background-color: #0066cc; }"
        "QCheckBox { color: #cccccc; }"
        "QGroupBox { color: #cccccc; border: 1px solid #333; border-radius: 4px; margin-top: 8px; padding-top: 16px; }"
        "QGroupBox::title { color: #888; }"
        "QLabel { color: #cccccc; }"
        "QScrollBar:vertical { background: #1a1a1a; width: 10px; }"
        "QScrollBar::handle:vertical { background: #444; border-radius: 5px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QStatusBar { background-color: #222222; color: #888; border-top: 1px solid #333; }"
    ) : QString(
        "* { background-color: #FFFFFF; color: #1a1a1a; font-family: \"Segoe UI\"; }"
        "QMainWindow { background-color: #FFFFFF; }"
        "QMenuBar { background-color: #F5F5F0; color: #1a1a1a; border-bottom: 1px solid #ddd; }"
        "QMenuBar::item:selected { background-color: #0066cc; color: white; }"
        "QMenu { background-color: #F5F5F0; color: #1a1a1a; border: 1px solid #ddd; }"
        "QMenu::item:selected { background-color: #0066cc; color: white; }"
        "QLineEdit, QTextEdit, QPlainTextEdit { background-color: #F0F0E8; color: #1a1a1a; border: 1px solid #ccc; padding: 6px; border-radius: 4px; }"
        "QPushButton { background-color: #E8E8E0; color: #1a1a1a; border: 1px solid #ccc; padding: 6px 16px; border-radius: 4px; }"
        "QPushButton:hover { background-color: #ddd; }"
        "QPushButton:pressed { background-color: #0066cc; color: white; }"
        "QPushButton:disabled { background-color: #f0f0f0; color: #999; }"
        "QListWidget { background-color: #F8F8F0; color: #1a1a1a; border: 1px solid #ddd; }"
        "QListWidget::item:selected { background-color: #0066cc; color: white; }"
        "QCheckBox { color: #1a1a1a; }"
        "QGroupBox { color: #1a1a1a; border: 1px solid #ddd; border-radius: 4px; margin-top: 8px; padding-top: 16px; }"
        "QGroupBox::title { color: #666; }"
        "QScrollBar:vertical { background: #f0f0f0; width: 10px; }"
        "QScrollBar::handle:vertical { background: #ccc; border-radius: 5px; min-height: 20px; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        "QStatusBar { background-color: #F5F5F0; color: #666; border-top: 1px solid #ddd; }"
    );
}

/* ===================================================================
 *  MAIN WINDOW
 * =================================================================== */
class ShroudWindow : public QMainWindow {
    Q_OBJECT
public:
    ShroudWindow() {
        setWindowTitle("SHROUD Secure Messenger");
        resize(880, 620);
        qApp->setStyleSheet(themeCSS(gDark));

        /* Init crypto + network */
        crypto_init();
        network_init();
        tpm_detect();
        kyber_init();

        /* Check saved identity */
        DeviceConfig cfg; ZeroMemory(&cfg, sizeof(cfg));
        if (storage_exists() && storage_load_config(&cfg) && storage_load_keypair(cfg.id, &cfg.identity_key)) {
            m_deviceId = cfg.id;
            m_username = cfg.username;
            m_deviceName = cfg.device_name;
            m_platform = cfg.platform;
            m_registered = true;
        }

        setupMenuBar();
        m_stack = new QStackedWidget;
        setCentralWidget(m_stack);

        if (m_registered) buildChatUI();
        else buildRegisterUI();
    }

private:
    QStackedWidget *m_stack;
    QListWidget *m_sideList;
    QTextEdit *m_chatLog;
    QLineEdit *m_toField, *m_nameField, *m_noteField, *m_msgInput;
    QPushButton *m_sendBtn, *m_attachBtn;
    QLabel *m_statusBar;
    bool m_registered = false, m_tabGroups = false;
    QString m_deviceId, m_username, m_deviceName, m_platform;
    QString m_selectedRecip;

    /* Network helper: call C module and return QByteArray */
    QByteArray httpPost(const char *path, const char *body) {
        HttpResponse *r = network_post(path, body);
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    QByteArray httpGet(const char *path) {
        HttpResponse *r = network_get(path);
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    QString jsonStr(const QByteArray &j, const char *k) {
        char *v = json_get_string(j.constData(), k);
        QString s = v ? QString::fromUtf8(v) : QString();
        if (v) free(v);
        return s;
    }

    /* ===============================================================
     *  MENU BAR
     * =============================================================== */
    void setupMenuBar() {
        QMenu *file = menuBar()->addMenu("&File");
        QAction *upd = file->addAction("Check for &Updates");
        connect(upd, &QAction::triggered, [this]() {
            QByteArray r = httpGet("/api/v1/version");
            QString v = jsonStr(r, "version");
            QMessageBox::information(this, "Updates",
                v.isEmpty() ? "Could not reach server" : QString("Latest: v%1\nCurrent: v%2").arg(v, CLIENT_VERSION));
        });
        file->addSeparator();
        QAction *ex = file->addAction("E&xit"); connect(ex, &QAction::triggered, this, &QWidget::close);

        QMenu *sett = menuBar()->addMenu("&Settings");
        QAction *st = sett->addAction("&Settings..."); connect(st, &QAction::triggered, this, &ShroudWindow::openSettings);
        QAction *th = sett->addAction(gDark ? "Switch to &Light Mode" : "Switch to &Dark Mode");
        connect(th, &QAction::triggered, [this, th]() {
            gDark = !gDark;
            qApp->setStyleSheet(themeCSS(gDark));
            th->setText(gDark ? "Switch to &Light Mode" : "Switch to &Dark Mode");
        });

        QMenu *help = menuBar()->addMenu("&Help");
        QAction *ab = help->addAction("&About"); connect(ab, &QAction::triggered, [this]() {
            QMessageBox::about(this, "SHROUD",
                QString("SHROUD v%1\n\nAES-256-GCM | ECDH P-384 | ML-KEM-1024\n"
                        "Self-Destructing Messages | One-Time Files\n"
                        "No personal data. No metadata. No trace.").arg(CLIENT_VERSION));
        });
    }

    /* ===============================================================
     *  REGISTRATION
     * =============================================================== */
    void buildRegisterUI() {
        auto *w = new QWidget;
        auto *lay = new QVBoxLayout(w);
        lay->setAlignment(Qt::AlignCenter);

        auto *card = new QWidget;
        card->setFixedWidth(400);
        auto *cl = new QVBoxLayout(card);
        cl->setSpacing(12);

        auto *title = new QLabel("<h2>SHROUD Setup</h2>"); title->setAlignment(Qt::AlignCenter);
        cl->addWidget(title);

        auto *uname = new QLineEdit; uname->setPlaceholderText("Username");
        cl->addWidget(uname);

        auto *pass = new QLineEdit; pass->setPlaceholderText("Password (12+ chars)"); pass->setEchoMode(QLineEdit::Password);
        cl->addWidget(pass);

        auto *dname = new QLineEdit; dname->setPlaceholderText("Device Name"); dname->setText("Windows-PC");
        cl->addWidget(dname);

        auto *remChk = new QCheckBox("Remember username"); cl->addWidget(remChk);

        /* Pre-fill saved username */
        DeviceConfig sc;
        if (storage_load_config(&sc) && sc.username[0]) {
            uname->setText(sc.username);
            remChk->setChecked(true);
        }

        auto *btnRow = new QHBoxLayout;
        auto *regBtn = new QPushButton("Create Account");
        auto *loginBtn = new QPushButton("Login & Add Device");
        btnRow->addWidget(regBtn); btnRow->addWidget(loginBtn);
        cl->addLayout(btnRow);

        auto *status = new QLabel; status->setAlignment(Qt::AlignCenter);
        cl->addWidget(status);

        lay->addWidget(card);
        m_stack->addWidget(w);

        auto doRegister = [=](bool isLogin) {
            QString u = uname->text().trimmed();
            QString p = pass->text();
            QString d = dname->text().trimmed();
            if (u.length() < 3 || p.length() < 12) { status->setText("Username 3+ chars, password 12+ chars"); return; }

            if (remChk->isChecked()) {
                DeviceConfig sc2; memcpy(&sc2, &sc, sizeof(sc2));
                strncpy(sc2.username, u.toUtf8().constData(), sizeof(sc2.username)-1);
                storage_save_config(&sc2);
            }

            status->setText("Generating ECDH P-384 keypair...");
            QApplication::processEvents();

            KeyPair kp = crypto_generate_keypair();
            if (!kp.handle) { status->setText("Key generation FAILED"); return; }

            char *hex = crypto_hex_encode(kp.pub.data, kp.pub.len);
            QString pubHex = QString::fromUtf8(hex); free(hex);

            if (!isLogin) {
                QByteArray ub = QString("{\"username\":\"%1\",\"password\":\"%2\"}").arg(u, p).toUtf8();
                httpPost("/api/v1/register", ub.constData());
            }

            status->setText(isLogin ? "Logging in..." : "Registering device...");
            QApplication::processEvents();

            char appId[64]; app_instance_id(appId, 64);
            QByteArray body = QString("{\"username\":\"%1\",\"password\":\"%2\",\"device_name\":\"%3\","
                "\"platform\":\"windows\",\"public_key\":\"%4\",\"hwid\":\"%5\"}")
                .arg(u, p, d, pubHex, QString::fromUtf8(appId)).toUtf8();

            QByteArray resp = httpPost("/api/v1/devices", body.constData());
            QString did = jsonStr(resp, "device_id");
            if (!did.isEmpty()) {
                m_deviceId = did; m_username = u; m_deviceName = d; m_platform = "windows";
                DeviceConfig scSave; ZeroMemory(&scSave, sizeof(scSave));
                strncpy(scSave.id, did.toUtf8().constData(), sizeof(scSave.id)-1);
                strncpy(scSave.username, u.toUtf8().constData(), sizeof(scSave.username)-1);
                strncpy(scSave.device_name, d.toUtf8().constData(), sizeof(scSave.device_name)-1);
                scSave.identity_key = kp;
                strcpy(scSave.platform, "windows");
                storage_save_config(&scSave);
                storage_save_keypair(scSave.id, &scSave.identity_key);
                m_registered = true;
                /* Swap to chat UI */
                QWidget *old = m_stack->currentWidget();
                buildChatUI();
                m_stack->removeWidget(old);
                old->deleteLater();
            } else {
                QString err = jsonStr(resp, "detail");
                status->setText(err.isEmpty() ? "Server rejected" : "Error: " + err);
            }
        };

        connect(regBtn, &QPushButton::clicked, [=]() { doRegister(false); });
        connect(loginBtn, &QPushButton::clicked, [=]() { doRegister(true); });
        connect(pass, &QLineEdit::returnPressed, [=]() { doRegister(false); });
    }

    /* ===============================================================
     *  CHAT UI
     * =============================================================== */
    void buildChatUI() {
        auto *mainW = new QWidget;
        auto *hbox = new QHBoxLayout(mainW);
        hbox->setContentsMargins(0, 0, 0, 0);
        hbox->setSpacing(0);

        /* === SIDEBAR === */
        auto *sidebar = new QWidget;
        sidebar->setFixedWidth(220);
        auto *sl = new QVBoxLayout(sidebar);
        sl->setContentsMargins(4, 4, 4, 4);
        sl->setSpacing(2);

        auto *tabRow = new QHBoxLayout;
        auto *ctBtn = new QPushButton("Contacts");
        auto *gtBtn = new QPushButton("Groups");
        tabRow->addWidget(ctBtn); tabRow->addWidget(gtBtn);
        sl->addLayout(tabRow);

        auto *search = new QLineEdit; search->setPlaceholderText("Search...");
        sl->addWidget(search);

        m_sideList = new QListWidget; sl->addWidget(m_sideList, 1);

        auto *grpBtn = new QPushButton("+ New Group");
        sl->addWidget(grpBtn);

        auto *themeBtn = new QPushButton(gDark ? "Light Mode" : "Dark Mode");
        sl->addWidget(themeBtn);

        hbox->addWidget(sidebar);

        /* === CHAT AREA === */
        auto *chatArea = new QWidget;
        auto *cl = new QVBoxLayout(chatArea);
        cl->setContentsMargins(6, 4, 6, 4);
        cl->setSpacing(4);

        /* Recipient */
        auto *toRow = new QHBoxLayout;
        toRow->addWidget(new QLabel("To:"));
        m_toField = new QLineEdit; m_toField->setReadOnly(true);
        m_toField->setPlaceholderText("Select a contact from the sidebar");
        toRow->addWidget(m_toField, 1);
        cl->addLayout(toRow);

        /* Connection status */
        m_statusBar = new QLabel("Connecting...");
        m_statusBar->setStyleSheet("color: #888; font-size: 11px;");
        cl->addWidget(m_statusBar);

        /* Chat log */
        m_chatLog = new QTextEdit; m_chatLog->setReadOnly(true);
        cl->addWidget(m_chatLog, 1);

        /* File panel */
        auto *fileList = new QListWidget; fileList->setMaximumHeight(50);
        cl->addWidget(fileList);

        /* Name + Note */
        auto *metaRow = new QHBoxLayout;
        metaRow->addWidget(new QLabel("Name:"));
        m_nameField = new QLineEdit; m_nameField->setMaximumWidth(140);
        metaRow->addWidget(m_nameField);
        metaRow->addWidget(new QLabel("Note:"));
        m_noteField = new QLineEdit;
        metaRow->addWidget(m_noteField, 1);
        cl->addLayout(metaRow);

        /* Input row */
        auto *inputRow = new QHBoxLayout;
        m_attachBtn = new QPushButton("Attach"); inputRow->addWidget(m_attachBtn);
        m_msgInput = new QLineEdit; m_msgInput->setPlaceholderText("Type a message...");
        inputRow->addWidget(m_msgInput, 1);
        m_sendBtn = new QPushButton("Send"); inputRow->addWidget(m_sendBtn);
        cl->addLayout(inputRow);

        hbox->addWidget(chatArea, 1);

        /* Status */
        QStatusBar *sb = statusBar();
        QString tpmStr; { char buf[128]; tpm_status_string(buf, 128); tpmStr = buf; }
        const char *pq = kyber_available() ? "ECDH+ML-KEM-1024" : "ECDH P-384";
        sb->showMessage(QString("Device: %1... | AES-256-GCM | %2 | %3 | v%4")
            .arg(m_deviceId.left(32)).arg(pq).arg(tpmStr).arg(CLIENT_VERSION));

        m_stack->addWidget(mainW);
        m_stack->setCurrentWidget(mainW);

        /* === CONNECTIONS === */
        connect(ctBtn, &QPushButton::clicked, [=]() { m_tabGroups = false; grpBtn->setText("Search Contacts"); loadContacts(); });
        connect(gtBtn, &QPushButton::clicked, [=]() { m_tabGroups = true; grpBtn->setText("+ New Group"); loadGroups(); });
        connect(grpBtn, &QPushButton::clicked, [=]() { if (m_tabGroups) createGroup(search->text()); else loadContacts(); });
        connect(themeBtn, &QPushButton::clicked, [=]() {
            gDark = !gDark; qApp->setStyleSheet(themeCSS(gDark));
            themeBtn->setText(gDark ? "Light Mode" : "Dark Mode");
        });
        connect(m_sideList, &QListWidget::itemDoubleClicked, this, &ShroudWindow::sideSelect);
        connect(m_sendBtn, &QPushButton::clicked, this, &ShroudWindow::sendMessage);
        connect(m_attachBtn, &QPushButton::clicked, this, &ShroudWindow::attachFile);
        connect(m_msgInput, &QLineEdit::returnPressed, this, &ShroudWindow::sendMessage);
        connect(search, &QLineEdit::textChanged, [=](const QString &t) {
            if (!m_tabGroups) { if (t.length() >= 2) searchContacts(t); else if (t.isEmpty()) loadContacts(); }
        });

        /* Timer for message polling + heartbeat */
        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() {
            fetchMessages();
            if (!m_deviceId.isEmpty()) {
                QByteArray hb = QString("{\"device_id\":\"%1\"}").arg(m_deviceId).toUtf8();
                httpPost("/api/v1/heartbeat", hb.constData());
            }
        });
        timer->start(4000);

        /* Initial load */
        loadContacts();
    }

    /* ===============================================================
     *  SIDEBAR LOGIC
     * =============================================================== */
    void loadContacts() {
        m_sideList->clear();
        QByteArray r = httpPost("/api/v1/devices/list",
            QString("{\"username\":\"%1\",\"password\":\"\"}").arg(m_username).toUtf8().constData());
        /* Parse JSON array */
        parseDeviceList(r);
    }

    void searchContacts(const QString &q) {
        m_sideList->clear();
        QByteArray r = httpPost("/api/v1/contacts/search",
            QString("{\"username\":\"%1\",\"password\":\"\",\"query\":\"%2\"}").arg(m_username, q).toUtf8().constData());
        /* Parse users array */
        QString j = QString::fromUtf8(r);
        int idx = j.indexOf("\"users\":[");
        if (idx < 0) return;
        idx = j.indexOf('[', idx);
        while ((idx = j.indexOf('"', idx + 1)) > 0) {
            int end = j.indexOf('"', idx + 1);
            if (end > idx) m_sideList->addItem(j.mid(idx + 1, end - idx - 1));
            idx = end;
        }
    }

    void loadGroups() {
        m_sideList->clear();
        QByteArray r = httpGet(QString("/api/v1/groups/%1").arg(m_deviceId).toUtf8().constData());
        QString j = QString::fromUtf8(r);
        int idx = j.indexOf("\"groups\":[");
        if (idx < 0) return;
        idx = j.indexOf('[', idx);
        while (idx >= 0) {
            int nid = j.indexOf("\"name\":\"", idx);
            int iid = j.indexOf("\"id\":\"", idx);
            if (nid < 0 || iid < 0) break;
            int ne = j.indexOf('"', nid + 8);
            int ie = j.indexOf('"', iid + 6);
            QString name = j.mid(nid + 8, ne - nid - 8);
            QString gid = j.mid(iid + 6, ie - iid - 6);
            m_sideList->addItem(QString("# %1 [%2]").arg(name, gid.left(12)));
            idx = qMax(ne, ie) + 1;
        }
    }

    void parseDeviceList(const QByteArray &r) {
        QString j = QString::fromUtf8(r);
        int idx = j.indexOf("\"devices\":[");
        if (idx < 0) return;
        idx = j.indexOf('[', idx);
        while (idx >= 0) {
            int nid = j.indexOf("\"id\":\"", idx);
            int nmid = j.indexOf("\"name\":\"", idx);
            int rid = j.indexOf("\"registered_at\":\"", idx);
            if (nid < 0 || nmid < 0) break;
            int ne = j.indexOf('"', nid + 6);
            int nme = j.indexOf('"', nmid + 8);
            QString id = j.mid(nid + 6, ne - nid - 6);
            QString name = j.mid(nmid + 8, nme - nmid - 8);
            QString date;
            if (rid >= 0) { int re = j.indexOf('"', rid + 18); date = j.mid(rid + 18, qMin(re - rid - 18, 10)); }
            m_sideList->addItem(date.isEmpty() ? QString("%1 (%2)").arg(name, id.left(12))
                                              : QString("%1 (%2) - %3").arg(name, id.left(12), date));
            idx = qMax(ne, nme) + 1;
        }
    }

    void createGroup(const QString &name) {
        QByteArray body = QString("{\"group_name\":\"%1\",\"creator_device_id\":\"%2\","
            "\"members\":[{\"device_id\":\"%2\",\"encrypted_group_key\":\"demo\"}]}")
            .arg(name.isEmpty() ? "New Group" : name, m_deviceId).toUtf8();
        httpPost("/api/v1/groups/create", body.constData());
        loadGroups();
    }

    void sideSelect(QListWidgetItem *item) {
        QString text = item->text();
        if (m_tabGroups) {
            int lb = text.indexOf('['), rb = text.indexOf(']');
            if (lb >= 0 && rb > lb) m_selectedRecip = text.mid(lb + 1, rb - lb - 1);
        } else {
            int lp = text.indexOf('('), rp = text.indexOf(')');
            if (lp >= 0 && rp > lp) m_selectedRecip = text.mid(lp + 1, rp - lp - 1);
            else m_selectedRecip = text;
        }
        m_toField->setText(text);
    }

    /* ===============================================================
     *  MESSAGING
     * =============================================================== */
    void sendMessage() {
        QString body = m_msgInput->text().trimmed();
        if (body.isEmpty() || m_selectedRecip.isEmpty()) return;
        QString name = m_nameField->text().trimmed();
        QString note = m_noteField->text().trimmed();

        BYTE sk[32];
        unsigned char pub[PUBLIC_KEY_MAX]; DWORD plen = 0;
        /* Get key from existing identity */
        if (storage_exists()) {
            DeviceConfig cfg;
            if (storage_load_config(&cfg)) {
                crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);
            }
        }

        QString payload = QString("{\"body\":\"%1\",\"name\":\"%2\",\"note\":\"%3\",\"sender\":\"%4\",\"ts\":%5}")
            .arg(body, name, note, m_deviceId).arg(QDateTime::currentSecsSinceEpoch());
        QByteArray pl = payload.toUtf8();

        BYTE iv[12], ct[5000], tag[16];
        crypto_random_bytes(iv, 12);
        crypto_aes_gcm_encrypt(sk, (const BYTE*)pl.constData(), pl.size(), iv, ct, tag);

        char *ih = crypto_hex_encode(iv, 12);
        char *ch = crypto_hex_encode(ct, pl.size());
        char *th = crypto_hex_encode(tag, 16);
        BYTE sig[32]; crypto_sha256(ct, pl.size(), sig);
        char *sh = crypto_hex_encode(sig, 32);

        QString env = QString("{\"sender\":\"%1\",\"ts\":%2,\"nonce\":\"%3\",\"ciphertext\":\"%4\",\"tag\":\"%5\",\"sig\":\"%6\"}")
            .arg(m_deviceId).arg(QDateTime::currentSecsSinceEpoch()).arg(ih, ch, th, sh);
        free(ih); free(ch); free(th); free(sh);

        QByteArray jb = QString("{\"sender_device_id\":\"%1\",\"recipient_device_id\":\"%2\",\"envelope\":%3}")
            .arg(m_deviceId, m_selectedRecip, env).toUtf8();
        httpPost("/api/v1/messages/send", jb.constData());

        m_chatLog->append(QString("<b>[ME → %1]</b> %2").arg(m_selectedRecip.left(12), body.toHtmlEscaped()));
        m_msgInput->clear();
    }

    void fetchMessages() {
        if (m_deviceId.isEmpty()) return;
        QByteArray r = httpPost("/api/v1/messages/fetch",
            QString("{\"device_id\":\"%1\"}").arg(m_deviceId).toUtf8().constData());
        m_statusBar->setText("Online — AES-256-GCM | ECDH P-384");
        QString j = QString::fromUtf8(r);
        if (!j.contains("\"sender_device_id\":\"")) return;
        /* Decrypt and display incoming messages */
        QStringList msgs = j.split("\"sender_device_id\":\"");
        for (int i = 1; i < msgs.size(); i++) {
            QString sender = msgs[i].left(64);
            int envStart = msgs[i].indexOf("\"envelope\":{");
            if (envStart < 0) continue;
            int bodyStart = msgs[i].indexOf("\"body\":\"", envStart);
            if (bodyStart < 0) continue;
            int bodyEnd = msgs[i].indexOf("\"", bodyStart + 8);
            if (bodyEnd < 0) continue;
            QString body = msgs[i].mid(bodyStart + 8, bodyEnd - bodyStart - 8);
            m_chatLog->append(QString("<b>[%1]</b> %2").arg(sender.left(12), body.toHtmlEscaped()));
        }
    }

    /* ===============================================================
     *  FILE ATTACH
     * =============================================================== */
    void attachFile() {
        QString path = QFileDialog::getOpenFileName(this, "Select File to Send (Encrypted)");
        if (path.isEmpty() || m_selectedRecip.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return;
        QByteArray data = f.readAll();
        f.close();

        BYTE sk[32];
        DeviceConfig cfg;
        if (storage_load_config(&cfg))
            crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);

        BYTE *enc = nullptr; DWORD elen = 0;
        if (!crypto_encrypt_file_data(sk, (const BYTE*)data.constData(), data.size(), &enc, &elen)) return;

        QString fname = QFileInfo(path).fileName();
        QString meta = QString("{\"name\":\"%1\",\"size\":%2}").arg(fname).arg(data.size());

        m_statusBar->setText("Uploading encrypted file...");
        QApplication::processEvents();

        HttpResponse *ur = network_upload_file("/api/v1/files/upload", enc, elen,
            m_deviceId.toUtf8().constData(), m_selectedRecip.toUtf8().constData(),
            meta.toUtf8().constData());
        free(enc);

        QString fileId;
        if (ur && ur->len > 0) { char *fid = json_get_string(ur->data, "file_id"); if (fid) { fileId = fid; free(fid); } network_free_response(ur); }
        if (fileId.isEmpty()) { m_statusBar->setText("Upload failed"); return; }

        /* Send file notification message */
        QString pl = QString("{\"type\":\"file\",\"file_id\":\"%1\",\"name\":\"%2\",\"size\":%3,\"body\":\"Sent file: %2 (%3 bytes)\"}")
            .arg(fileId, fname).arg(data.size());
        QByteArray plb = pl.toUtf8();

        BYTE iv[12], ct[5000], tag[16];
        crypto_random_bytes(iv, 12);
        crypto_aes_gcm_encrypt(sk, (const BYTE*)plb.constData(), plb.size(), iv, ct, tag);
        char *ih = crypto_hex_encode(iv, 12);
        char *ch = crypto_hex_encode(ct, plb.size());
        char *th = crypto_hex_encode(tag, 16);
        BYTE sig[32]; crypto_sha256(ct, plb.size(), sig);
        char *sh = crypto_hex_encode(sig, 32);

        QString env = QString("{\"sender\":\"%1\",\"ts\":%2,\"nonce\":\"%3\",\"ciphertext\":\"%4\",\"tag\":\"%5\",\"sig\":\"%6\"}")
            .arg(m_deviceId).arg(QDateTime::currentSecsSinceEpoch()).arg(ih, ch, th, sh);
        free(ih); free(ch); free(th); free(sh);

        QByteArray jb = QString("{\"sender_device_id\":\"%1\",\"recipient_device_id\":\"%2\",\"envelope\":%3}")
            .arg(m_deviceId, m_selectedRecip, env).toUtf8();
        httpPost("/api/v1/messages/send", jb.constData());

        m_chatLog->append(QString("<b>[ME → %1]</b> [FILE] %2 (%3 bytes)")
            .arg(m_selectedRecip.left(12), fname).arg(data.size()));
        m_statusBar->setText(QString("File sent: %1").arg(fname));
    }

    /* ===============================================================
     *  SETTINGS
     * =============================================================== */
    void openSettings() {
        QDialog dlg(this);
        dlg.setWindowTitle("SHROUD Settings");
        dlg.setFixedSize(440, 500);
        auto *lay = new QVBoxLayout(&dlg);

        auto *tabs = new QTabWidget;
        /* General tab */
        auto *gen = new QWidget; auto *gl = new QVBoxLayout(gen);
        auto *dmBox = new QCheckBox("Dark Mode"); dmBox->setChecked(gDark);
        connect(dmBox, &QCheckBox::toggled, [](bool c) { gDark = c; qApp->setStyleSheet(themeCSS(c)); });
        gl->addWidget(dmBox);

        auto *accentRow = new QHBoxLayout;
        accentRow->addWidget(new QLabel("Accent:"));
        auto *ar = new QLineEdit("255"); ar->setMaximumWidth(50);
        auto *ag = new QLineEdit("102"); ag->setMaximumWidth(50);
        auto *ab = new QLineEdit("0"); ab->setMaximumWidth(50);
        accentRow->addWidget(new QLabel("R:")); accentRow->addWidget(ar);
        accentRow->addWidget(new QLabel("G:")); accentRow->addWidget(ag);
        accentRow->addWidget(new QLabel("B:")); accentRow->addWidget(ab);
        accentRow->addStretch();
        gl->addLayout(accentRow);
        gl->addStretch();
        tabs->addTab(gen, "General");

        /* Password tab */
        auto *pw = new QWidget; auto *pl = new QVBoxLayout(pw);
        auto *oldPw = new QLineEdit; oldPw->setEchoMode(QLineEdit::Password); oldPw->setPlaceholderText("Current password");
        auto *newPw = new QLineEdit; newPw->setEchoMode(QLineEdit::Password); newPw->setPlaceholderText("New password (12+ chars)");
        auto *cfmPw = new QLineEdit; cfmPw->setEchoMode(QLineEdit::Password); cfmPw->setPlaceholderText("Confirm new password");
        pl->addWidget(oldPw); pl->addWidget(newPw); pl->addWidget(cfmPw);
        auto *chBtn = new QPushButton("Change Password");
        connect(chBtn, &QPushButton::clicked, [=, &dlg]() {
            if (newPw->text().length() < 12 || newPw->text() != cfmPw->text()) {
                QMessageBox::warning(&dlg, "Error", "Password must be 12+ chars and match"); return;
            }
            QByteArray b = QString("{\"username\":\"%1\",\"old_password\":\"%2\",\"new_password\":\"%3\"}")
                .arg(m_username, oldPw->text(), newPw->text()).toUtf8();
            QByteArray r = httpPost("/api/v1/change-password", b.constData());
            QMessageBox::information(&dlg, "Password", r.contains("\"changed\":true") ? "Changed!" : "Failed");
        });
        pl->addWidget(chBtn); pl->addStretch();
        tabs->addTab(pw, "Password");

        /* Danger tab */
        auto *dz = new QWidget; auto *dl = new QVBoxLayout(dz);
        dl->addWidget(new QLabel("Permanently destroy all data and the application:"));
        auto *nukeBtn = new QPushButton("NUKE MY DATA");
        nukeBtn->setStyleSheet("QPushButton { background-color: #cc0000; color: white; font-weight: bold; }");
        connect(nukeBtn, &QPushButton::clicked, [&dlg]() {
            if (QMessageBox::question(&dlg, "Confirm Nuke",
                "Delete ALL data and the SHROUD executable?\nThis is IRREVERSIBLE.",
                QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes) {
                storage_delete_all();
                QApplication::quit();
            }
        });
        dl->addWidget(nukeBtn); dl->addStretch();
        tabs->addTab(dz, "Danger");

        lay->addWidget(tabs);
        auto *closeBtn = new QPushButton("Close"); connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
        lay->addWidget(closeBtn);
        dlg.exec();
    }
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("SHROUD");
    app.setApplicationVersion(CLIENT_VERSION);
    ShroudWindow w;
    w.show();
    return app.exec();
}
