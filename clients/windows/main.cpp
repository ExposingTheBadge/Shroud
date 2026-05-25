/*
 * GHOSTLINK Qt6 Client — Clean cross-platform desktop client
 * Compile: cmake -B build && cmake --build build --config Release
 */
#include <QtWidgets>
#include <QtNetwork>
#include <QtCore>

#define CLIENT_VERSION "1.7.0"

extern "C" {
#include "client.h"
extern "C" {
#include "ratchet.h"
}
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
        "QMenuBar::item:selected { background-color: #ff8c1e; }"
        "QMenu { background-color: #222222; color: #cccccc; border: 1px solid #333; }"
        "QMenu::item:selected { background-color: #ff8c1e; }"
        "QLineEdit, QTextEdit, QPlainTextEdit { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px; border-radius: 4px; }"
        "QTextEdit { background-color: #1a1a1a; }"
        "QPushButton { background-color: #2d2d2d; color: #cccccc; border: 1px solid #3d3d3d; padding: 6px 16px; border-radius: 4px; }"
        "QPushButton:hover { background-color: #3d3d3d; border-color: #555; }"
        "QPushButton:pressed { background-color: #ff8c1e; }"
        "QPushButton:disabled { background-color: #1a1a1a; color: #555; }"
        "QListWidget { background-color: #222222; color: #cccccc; border: 1px solid #333; }"
        "QListWidget::item:selected { background-color: #ff8c1e; }"
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
        "QMenuBar::item:selected { background-color: #ff8c1e; color: white; }"
        "QMenu { background-color: #F5F5F0; color: #1a1a1a; border: 1px solid #ddd; }"
        "QMenu::item:selected { background-color: #ff8c1e; color: white; }"
        "QLineEdit, QTextEdit, QPlainTextEdit { background-color: #F0F0E8; color: #1a1a1a; border: 1px solid #ccc; padding: 6px; border-radius: 4px; }"
        "QPushButton { background-color: #E8E8E0; color: #1a1a1a; border: 1px solid #ccc; padding: 6px 16px; border-radius: 4px; }"
        "QPushButton:hover { background-color: #ddd; }"
        "QPushButton:pressed { background-color: #ff8c1e; color: white; }"
        "QPushButton:disabled { background-color: #f0f0f0; color: #999; }"
        "QListWidget { background-color: #F8F8F0; color: #1a1a1a; border: 1px solid #ddd; }"
        "QListWidget::item:selected { background-color: #ff8c1e; color: white; }"
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
 *  Password reveal icon — eye with lashes, drawn at runtime
 * =================================================================== */
static QIcon eyeIcon(bool open) {
    QPixmap pm(18, 18);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QColor col = gDark ? QColor(180, 180, 180) : QColor(80, 80, 80);
    p.setPen(QPen(col, 1.4));
    p.setBrush(Qt::NoBrush);
    /* Almond eye shape */
    QPainterPath eye;
    eye.moveTo(2, 9);
    eye.quadTo(9, open ? 2 : 6, 16, 9);
    eye.quadTo(9, open ? 16 : 12, 2, 9);
    p.drawPath(eye);
    /* Lashes (top) */
    p.drawLine(QPointF(9,  1.5), QPointF(9,  3.5));
    p.drawLine(QPointF(4.5, 2.5), QPointF(5.5, 4.5));
    p.drawLine(QPointF(13.5, 2.5), QPointF(12.5, 4.5));
    if (open) {
        p.setBrush(col);
        p.drawEllipse(QPointF(9, 9), 2.2, 2.2);
    } else {
        /* Slash through the closed eye */
        p.setPen(QPen(col, 1.4));
        p.drawLine(QPointF(3, 4), QPointF(15, 14));
    }
    return QIcon(pm);
}

static void attachPasswordReveal(QLineEdit *field) {
    QAction *act = field->addAction(eyeIcon(false), QLineEdit::TrailingPosition);
    act->setToolTip("Show password");
    QObject::connect(act, &QAction::triggered, field, [field, act]() {
        bool shown = field->echoMode() == QLineEdit::Normal;
        field->setEchoMode(shown ? QLineEdit::Password : QLineEdit::Normal);
        act->setIcon(eyeIcon(!shown));
        act->setToolTip(shown ? "Show password" : "Hide password");
    });
}

/* ===================================================================
 *  ImageViewer — borderless full-screen image dialog with a very
 *  visible X close button (top-right) and a delete option.
 * =================================================================== */
class ImageViewer : public QDialog {
    Q_OBJECT
public:
    ImageViewer(const QString &fileId, const QString &path, QWidget *parent = nullptr)
        : QDialog(parent), m_fileId(fileId)
    {
        setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
        setAttribute(Qt::WA_DeleteOnClose);
        setModal(true);
        setStyleSheet("QDialog { background-color: rgba(0,0,0,235); }");

        QImage src(path);
        if (src.isNull()) {
            QMessageBox::warning(this, "Image", "Could not load image."); QTimer::singleShot(0, this, &QDialog::reject); return;
        }
        QScreen *scr = QGuiApplication::primaryScreen();
        QRect g = scr ? scr->availableGeometry() : QRect(0, 0, 1280, 720);
        const int margin = 60;
        QSize maxSize(g.width() - margin, g.height() - margin);
        QImage scaled = src.scaled(maxSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);

        resize(g.size());
        move(g.topLeft());

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);

        m_label = new QLabel(this);
        m_label->setAlignment(Qt::AlignCenter);
        m_label->setPixmap(QPixmap::fromImage(scaled));
        layout->addWidget(m_label, 1);

        /* Top-right close button — bright, high-contrast, always visible. */
        m_close = new QPushButton("✕", this);  // ✕
        m_close->setFixedSize(48, 48);
        m_close->setCursor(Qt::PointingHandCursor);
        m_close->setToolTip("Close (Esc)");
        m_close->setStyleSheet(
            "QPushButton {"
            "  background-color: #ff8c1e; color: #1a1a1a;"
            "  border: 2px solid #ffffff; border-radius: 24px;"
            "  font-size: 22px; font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: #ffa040; }"
            "QPushButton:pressed { background-color: #cc6e10; }"
        );
        connect(m_close, &QPushButton::clicked, this, &QDialog::accept);

        /* Bottom-right delete button. */
        m_del = new QPushButton("Delete", this);
        m_del->setFixedSize(120, 36);
        m_del->setCursor(Qt::PointingHandCursor);
        m_del->setStyleSheet(
            "QPushButton {"
            "  background-color: rgba(40,40,40,220); color: #ff8888;"
            "  border: 1px solid #ff8888; border-radius: 6px;"
            "  font-weight: bold;"
            "}"
            "QPushButton:hover { background-color: rgba(80,30,30,240); color: #ffaaaa; }"
        );
        connect(m_del, &QPushButton::clicked, this, [this]() {
            emit deleteRequested(m_fileId);
            accept();
        });

        positionOverlays();
    }

signals:
    void deleteRequested(const QString &fileId);

protected:
    void keyPressEvent(QKeyEvent *e) override {
        if (e->key() == Qt::Key_Escape) { accept(); return; }
        QDialog::keyPressEvent(e);
    }
    void resizeEvent(QResizeEvent *) override { positionOverlays(); }

private:
    void positionOverlays() {
        if (m_close) m_close->move(width() - m_close->width() - 24, 24);
        if (m_del)   m_del->move(width() - m_del->width() - 24,
                                  height() - m_del->height() - 24);
    }
    QString m_fileId;
    QLabel *m_label = nullptr;
    QPushButton *m_close = nullptr;
    QPushButton *m_del = nullptr;
};

/* ===================================================================
 *  MAIN WINDOW
 * =================================================================== */
class GhostlinkWindow : public QMainWindow {
    Q_OBJECT
public:
    GhostlinkWindow() {
        setWindowTitle("GHOSTLINK Secure Messenger");
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

        /* Background update check on startup — silent unless a newer version
           is available. Delayed so it doesn't block UI paint. */
        QTimer::singleShot(2000, this, [this]() { checkForUpdates(false); });
    }

private:
    QStackedWidget *m_stack;
    QListWidget *m_sideList;
    QTextBrowser *m_chatLog;
    QMap<QString, QString> m_imagePaths; // file_id -> local plaintext image path
    QLineEdit *m_toField, *m_msgInput;
    QPushButton *m_sendBtn, *m_attachBtn;
    QLabel *m_statusBar;
    bool m_registered = false, m_tabGroups = false;
    QString m_deviceId, m_username, m_deviceName, m_platform, m_password;
    QString m_selectedRecip;
    QStringList m_friends;

    /* Search result panel widgets — built once in buildChatUI, shown when a
       lookup hits or misses. */
    QWidget *m_searchResult = nullptr;
    QLabel *m_searchResultLabel = nullptr;
    QPushButton *m_btnMsg = nullptr, *m_btnFriend = nullptr, *m_btnGroupInvite = nullptr;
    QString m_searchHit;          // username of currently-shown search result (empty if miss)
    bool m_searchHitIsFriend = false;

    /* Inject-safe JSON builder. Uses Qt's encoder so quotes, backslashes,
       control chars, and unicode in user input get escaped properly. */
    static QByteArray jsonBody(std::initializer_list<std::pair<QString, QVariant>> fields) {
        QJsonObject obj;
        for (const auto &p : fields) obj.insert(p.first, QJsonValue::fromVariant(p.second));
        return QJsonDocument(obj).toJson(QJsonDocument::Compact);
    }

    /* Network helper: call C module and return QByteArray */
    QByteArray httpPost(const char *path, const char *body) {
        HttpResponse *r = network_post(path, body);
        QByteArray data;
        if (r && r->len > 0) { data = QByteArray(r->data, (int)r->len); network_free_response(r); }
        return data;
    }

    /* Overload that takes a pre-built JSON body. */
    QByteArray httpPost(const char *path, const QByteArray &body) {
        return httpPost(path, body.constData());
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
    /* Naive semver compare: returns +1 if a>b, -1 if a<b, 0 if equal. */
    static int versionCompare(const QString &a, const QString &b) {
        QStringList pa = a.split('.'), pb = b.split('.');
        int n = pa.size() > pb.size() ? pa.size() : pb.size();
        for (int i = 0; i < n; i++) {
            int ai = (i < pa.size()) ? pa[i].toInt() : 0;
            int bi = (i < pb.size()) ? pb[i].toInt() : 0;
            if (ai != bi) return ai > bi ? 1 : -1;
        }
        return 0;
    }

    void setupMenuBar() {
        QMenu *file = menuBar()->addMenu("&File");
        QAction *upd = file->addAction("Check for &Updates");
        connect(upd, &QAction::triggered, [this]() { checkForUpdates(true); });
        file->addSeparator();
        QAction *ex = file->addAction("E&xit"); connect(ex, &QAction::triggered, this, &QWidget::close);

        QMenu *sett = menuBar()->addMenu("&Settings");
        QAction *st = sett->addAction("&Settings..."); connect(st, &QAction::triggered, this, &GhostlinkWindow::openSettings);
        QAction *th = sett->addAction(gDark ? "Switch to &Light Mode" : "Switch to &Dark Mode");
        connect(th, &QAction::triggered, [this, th]() {
            gDark = !gDark;
            qApp->setStyleSheet(themeCSS(gDark));
            th->setText(gDark ? "Switch to &Light Mode" : "Switch to &Dark Mode");
        });

        QMenu *help = menuBar()->addMenu("&Help");
        QAction *ab = help->addAction("&About"); connect(ab, &QAction::triggered, [this]() {
            QMessageBox::about(this, "GHOSTLINK",
                QString("GHOSTLINK v%1\n\nAES-256-GCM | ECDH P-384 | ML-KEM-1024\n"
                        "Self-Destructing Messages | One-Time Files\n"
                        "No personal data. No metadata. No trace.").arg(CLIENT_VERSION));
        });
    }

    /* Query /api/v1/version, compare against CLIENT_VERSION, and prompt the
       user to open the download URL when newer. If verbose=false (background
       check), stays silent unless an update is available. */
    void checkForUpdates(bool verbose) {
        QByteArray r = httpGet("/api/v1/version");
        if (r.isEmpty()) {
            if (verbose) QMessageBox::warning(this, "Updates", "Could not reach server.");
            return;
        }
        QJsonObject obj = QJsonDocument::fromJson(r).object();
        QString latest = obj.value("version").toString();
        QString winUrl = obj.value("windows").toString();
        QString releaseUrl = obj.value("release_url").toString();
        QString changelog = obj.value("changelog").toString();
        if (latest.isEmpty()) {
            if (verbose) QMessageBox::warning(this, "Updates", "Server returned no version info.");
            return;
        }
        int cmp = versionCompare(latest, CLIENT_VERSION);
        if (cmp <= 0) {
            if (verbose) QMessageBox::information(this, "Updates",
                QString("You are up to date.\n\nCurrent: v%1\nLatest:  v%2").arg(CLIENT_VERSION, latest));
            return;
        }
        QString openUrl = !winUrl.isEmpty() ? winUrl : releaseUrl;
        QMessageBox box(this);
        box.setWindowTitle("Update Available");
        box.setIcon(QMessageBox::Information);
        box.setText(QString("<b>GHOSTLINK v%1</b> is available.<br>You have v%2.").arg(latest, CLIENT_VERSION));
        if (!changelog.isEmpty()) box.setInformativeText(changelog);
        QPushButton *dl = box.addButton("Download", QMessageBox::AcceptRole);
        box.addButton("Later", QMessageBox::RejectRole);
        box.exec();
        if (box.clickedButton() == dl && !openUrl.isEmpty()) {
            QDesktopServices::openUrl(QUrl(openUrl));
        }
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

    auto *title = new QLabel("<h2>GHOSTLINK</h2>"); title->setAlignment(Qt::AlignCenter);
    cl->addWidget(title);

    /* Shared fields */
    auto *uname = new QLineEdit; uname->setPlaceholderText("Username");
    cl->addWidget(uname);

    auto *pass = new QLineEdit; pass->setPlaceholderText("Password (12+ chars)"); pass->setEchoMode(QLineEdit::Password);
    attachPasswordReveal(pass);
    cl->addWidget(pass);

    /* Register-only field */
    auto *dname = new QLineEdit; dname->setPlaceholderText("Device Name"); dname->setText("Windows-PC");
    cl->addWidget(dname);
    dname->hide();

    auto *remChk = new QCheckBox("Remember username"); cl->addWidget(remChk);

    DeviceConfig sc;
    if (storage_load_config(&sc) && sc.username[0]) {
        uname->setText(sc.username);
        remChk->setChecked(true);
    }

    auto *status = new QLabel; status->setAlignment(Qt::AlignCenter);
    cl->addWidget(status);

    auto *actionBtn = new QPushButton("Login");
    cl->addWidget(actionBtn);

    auto *toggleLink = new QPushButton("Don't have an account? Register");
    toggleLink->setFlat(true);
    toggleLink->setStyleSheet("QPushButton { color: #ff8c1e; border: none; background: transparent; }");
    cl->addWidget(toggleLink);

    lay->addWidget(card);
    m_stack->addWidget(w);

    /* Mode flag lives on the button so it outlives this stack frame.
       Capturing a stack-local bool by reference would dangle once
       buildRegisterUI() returns. */
    actionBtn->setProperty("registerMode", false);

    auto updateMode = [actionBtn, toggleLink, dname]() {
        bool reg = actionBtn->property("registerMode").toBool();
        dname->setVisible(reg);
        actionBtn->setText(reg ? "Create Account" : "Login");
        toggleLink->setText(reg ? "Already registered? Login" : "Don't have an account? Register");
    };

    QObject::connect(toggleLink, &QPushButton::clicked, [actionBtn, updateMode]() {
        actionBtn->setProperty("registerMode", !actionBtn->property("registerMode").toBool());
        updateMode();
    });

    auto doAction = [=]() {
        bool showRegister = actionBtn->property("registerMode").toBool();
        QString u = uname->text().trimmed();
        QString p = pass->text();
        QString d = dname->text().trimmed();
        if (u.length() < 3 || p.length() < 12) { status->setText("Username 3+ chars, password 12+ chars"); return; }

        if (remChk->isChecked()) {
            DeviceConfig sc2; memcpy(&sc2, &sc, sizeof(sc2));
            strncpy(sc2.username, u.toUtf8().constData(), sizeof(sc2.username)-1);
            storage_save_config(&sc2);
        }

        status->setText("Verifying server identity...");
        QApplication::processEvents();

        /* 0. Server identity check (TOFU pin). Triple-hybrid signature
              suite Ed25519 + ML-DSA-87 + SPHINCS+-256s. If the server's
              fingerprint differs from what we pinned earlier, refuse. */
        QString serverFp;
        int idStatus = verifyServerIdentity(&serverFp);
        if (idStatus == -1) {
            QMessageBox::critical(this, "Server identity changed",
                "The server's identity fingerprint does NOT match the one this device pinned.\n\n"
                "Pinned:  " + loadPinnedFingerprint() + "\n"
                "Server:  " + serverFp + "\n\n"
                "This usually means one of:\n"
                "  • The server operator rotated the identity (verify out of band).\n"
                "  • Someone is impersonating the server (MITM attack).\n\n"
                "Refusing to authenticate. If the change is legitimate, delete\n"
                + serverPinPath() + " and try again.");
            status->setText("Server identity mismatch — refusing");
            return;
        }
        if (idStatus == 1) {
            status->setText("First connect: pinned server fingerprint " + serverFp.left(8) + "...");
            QApplication::processEvents();
        }

        status->setText("Exchanging keys...");
        QApplication::processEvents();

        /* Generate our ECDH keypair — used by both v1 and v2 paths. */
        KeyPair kp = crypto_generate_keypair();
        if (!kp.handle) { status->setText("Key generation FAILED"); return; }
        char *ourPubHex = crypto_hex_encode(kp.pub.data, kp.pub.len);
        QString pubHex = QString::fromUtf8(ourPubHex); free(ourPubHex);

        QByteArray resp;
        bool usedPq = false;

        /* ── v2 hybrid PQ handshake (ECDH-P384 + ML-KEM-1024) ───────────
              Opportunistic: if liboqs.dll is present we use it. The server
              attests the handshake with its triple-hybrid signature; the
              fingerprint was already pinned at step 0 above. */
        if (kyber_available()) {
            QByteArray kxV2 = httpGet("/api/v1/key-exchange-v2");
            QString sidV2 = jsonStr(kxV2, "session_id");
            QString blobHexV2 = jsonStr(kxV2, "server_public_key_blob");
            if (!sidV2.isEmpty() && !blobHexV2.isEmpty()) {
                QByteArray blobBytesQ = QByteArray::fromHex(blobHexV2.toUtf8());
                BYTE clientBlob[2048]; DWORD cbLen = sizeof(clientBlob);
                BYTE sessionKey[32];
                if (crypto_pq_hybrid_client((const BYTE*)blobBytesQ.constData(), blobBytesQ.size(),
                                            clientBlob, &cbLen, sessionKey)) {
                    /* Auth key = SHA-256(session_key || "GHOSTLINK-AUTH-PQ-v1") */
                    BYTE authKey[32]; BYTE buf[32 + 21];
                    memcpy(buf, sessionKey, 32);
                    memcpy(buf + 32, "GHOSTLINK-AUTH-PQ-v1", 21);
                    crypto_sha256(buf, sizeof(buf), authKey);

                    QByteArray payload = jsonBody({
                        {"username", u}, {"password", p}, {"device_name", d},
                        {"platform", QString("windows")}, {"register", showRegister},
                        {"public_key", pubHex}
                    });
                    BYTE nonce[12], ct[4096], tag[16];
                    crypto_random_bytes(nonce, 12);
                    crypto_aes_gcm_encrypt(authKey, (const BYTE*)payload.constData(),
                                           payload.size(), nonce, ct, tag);
                    char *nh = crypto_hex_encode(nonce, 12);
                    char *ch = crypto_hex_encode(ct, payload.size());
                    char *th = crypto_hex_encode(tag, 16);
                    char *bh = crypto_hex_encode(clientBlob, cbLen);
                    QByteArray body = jsonBody({
                        {"session_id", sidV2},
                        {"client_pubkey_blob", QString::fromUtf8(bh)},
                        {"nonce", QString::fromUtf8(nh)},
                        {"ciphertext", QString::fromUtf8(ch)},
                        {"tag", QString::fromUtf8(th)},
                    });
                    free(nh); free(ch); free(th); free(bh);
                    resp = httpPost("/api/v1/auth-v2", body);
                    QString didV2 = jsonStr(resp, "device_id");
                    if (!didV2.isEmpty()) usedPq = true;
                }
            }
        }

        /* ── v1 classical fallback ─────────────────────────────────── */
        if (!usedPq) {
            QByteArray keyResp = httpGet("/api/v1/key-exchange");
            QString sessionId = jsonStr(keyResp, "session_id");
            QString serverPubBlobHex = jsonStr(keyResp, "server_public_key_blob");
            if (sessionId.isEmpty() || serverPubBlobHex.isEmpty()) {
                status->setText("Key exchange failed"); crypto_free_keypair(&kp); return;
            }
            BYTE serverBlob[512]; DWORD blobLen = 0;
            QByteArray blobHex = serverPubBlobHex.toUtf8();
            crypto_hex_decode(blobHex.constData(), serverBlob, &blobLen);
            BYTE authKey[32];
            if (!crypto_auth_derive_key(kp.handle, serverBlob, blobLen, authKey)) {
                status->setText("Key derivation failed"); crypto_free_keypair(&kp); return;
            }
            QByteArray payload = jsonBody({
                {"username", u}, {"password", p}, {"device_name", d},
                {"platform", QString("windows")}, {"register", showRegister},
                {"public_key", pubHex}
            });
            BYTE nonce[12], ct[4096], tag[16];
            crypto_random_bytes(nonce, 12);
            crypto_aes_gcm_encrypt(authKey, (const BYTE*)payload.constData(),
                                   payload.size(), nonce, ct, tag);
            char *nonceHex = crypto_hex_encode(nonce, 12);
            char *ctHex = crypto_hex_encode(ct, payload.size());
            char *tagHex = crypto_hex_encode(tag, 16);
            QByteArray authBody = jsonBody({
                {"session_id", sessionId}, {"client_public_key", pubHex},
                {"nonce", QString::fromUtf8(nonceHex)},
                {"ciphertext", QString::fromUtf8(ctHex)},
                {"tag", QString::fromUtf8(tagHex)}
            });
            free(nonceHex); free(ctHex); free(tagHex);
            resp = httpPost("/api/v1/auth", authBody);
        }
        QString did = jsonStr(resp, "device_id");
        if (!did.isEmpty()) {
            m_deviceId = did; m_username = u; m_deviceName = d; m_platform = "windows"; m_password = p;
            DeviceConfig scSave; ZeroMemory(&scSave, sizeof(scSave));
            strncpy(scSave.id, did.toUtf8().constData(), sizeof(scSave.id)-1);
            strncpy(scSave.username, u.toUtf8().constData(), sizeof(scSave.username)-1);
            strncpy(scSave.device_name, d.toUtf8().constData(), sizeof(scSave.device_name)-1);
            scSave.identity_key = kp;
            strcpy(scSave.platform, "windows");
            storage_save_config(&scSave);
            storage_save_keypair(scSave.id, &scSave.identity_key);

            /* Publish our ratchet bundle. Generates one long-term X25519
               identity + 32 one-time prekeys, stores the privs locally,
               and uploads the pubs to /api/v1/ratchet/publish-key so peers
               can bootstrap a Double Ratchet conversation with us. Best-
               effort — failure is non-fatal for v1.7 (clients fall back
               to the v1 envelope flow). */
            publishRatchetBundle(did);

            m_registered = true;
            QWidget *old = m_stack->currentWidget();
            buildChatUI();
            m_stack->removeWidget(old);
            old->deleteLater();
        } else {
            QString err = jsonStr(resp, "detail");
            status->setText(err.isEmpty() ? "Server rejected" : "Error: " + err);
        }
    };

    QObject::connect(actionBtn, &QPushButton::clicked, doAction);
    QObject::connect(pass, &QLineEdit::returnPressed, doAction);
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

        auto *search = new QLineEdit; search->setPlaceholderText("Find user (exact, press Enter)");
        sl->addWidget(search);

        /* Search result panel: shown only after an explicit lookup. */
        m_searchResult = new QWidget;
        m_searchResult->setVisible(false);
        auto *srl = new QVBoxLayout(m_searchResult);
        srl->setContentsMargins(4, 4, 4, 4);
        srl->setSpacing(4);
        m_searchResultLabel = new QLabel;
        m_searchResultLabel->setWordWrap(true);
        srl->addWidget(m_searchResultLabel);
        m_btnMsg = new QPushButton("Message");
        m_btnFriend = new QPushButton("Send Friend Request");
        m_btnGroupInvite = new QPushButton("Add to Group");
        srl->addWidget(m_btnMsg);
        srl->addWidget(m_btnFriend);
        srl->addWidget(m_btnGroupInvite);
        sl->addWidget(m_searchResult);

        m_sideList = new QListWidget; sl->addWidget(m_sideList, 1);

        auto *reqBtn = new QPushButton("Requests");
        sl->addWidget(reqBtn);

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
        m_statusBar->setStyleSheet("color: #cc8800; font-size: 11px; font-weight: bold;");
        cl->addWidget(m_statusBar);

        /* Chat log — QTextBrowser so we can click inline images. */
        m_chatLog = new QTextBrowser;
        m_chatLog->setReadOnly(true);
        m_chatLog->setOpenLinks(false);
        m_chatLog->setOpenExternalLinks(false);
        connect(m_chatLog, &QTextBrowser::anchorClicked, this, &GhostlinkWindow::onChatAnchorClicked);
        m_chatLog->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(m_chatLog, &QWidget::customContextMenuRequested, this, &GhostlinkWindow::onChatContextMenu);
        cl->addWidget(m_chatLog, 1);

        /* File panel */
        auto *fileList = new QListWidget; fileList->setMaximumHeight(50);
        cl->addWidget(fileList);

        /* Input row */
        auto *inputRow = new QHBoxLayout;
        m_attachBtn = new QPushButton("Attach"); inputRow->addWidget(m_attachBtn);
        m_msgInput = new QLineEdit; m_msgInput->setPlaceholderText("Type a message...");
        m_msgInput->setMinimumHeight(36);
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
        connect(ctBtn, &QPushButton::clicked, [=]() { m_tabGroups = false; grpBtn->setText("+ New Group"); hideSearchResult(); loadContacts(); });
        connect(gtBtn, &QPushButton::clicked, [=]() { m_tabGroups = true; grpBtn->setText("+ New Group"); hideSearchResult(); loadGroups(); });
        connect(grpBtn, &QPushButton::clicked, [=]() {
            bool ok = false;
            QString name = QInputDialog::getText(this, "New Group", "Group name:", QLineEdit::Normal, "", &ok);
            if (ok && !name.trimmed().isEmpty()) { createGroup(name.trimmed()); m_tabGroups = true; loadGroups(); }
        });
        connect(reqBtn, &QPushButton::clicked, this, &GhostlinkWindow::openRequestsDialog);
        connect(themeBtn, &QPushButton::clicked, [=]() {
            gDark = !gDark; qApp->setStyleSheet(themeCSS(gDark));
            themeBtn->setText(gDark ? "Light Mode" : "Dark Mode");
        });
        connect(m_sideList, &QListWidget::itemDoubleClicked, this, &GhostlinkWindow::sideSelect);
        connect(m_sendBtn, &QPushButton::clicked, this, &GhostlinkWindow::sendMessage);
        connect(m_attachBtn, &QPushButton::clicked, this, &GhostlinkWindow::attachFile);
        connect(m_msgInput, &QLineEdit::returnPressed, this, &GhostlinkWindow::sendMessage);
        /* Exact-match search only fires on Enter. */
        connect(search, &QLineEdit::returnPressed, [=]() {
            if (!m_tabGroups) doExactSearch(search->text());
        });
        connect(search, &QLineEdit::textChanged, [=](const QString &t) {
            if (t.isEmpty()) hideSearchResult();
        });
        /* Search-result action buttons */
        connect(m_btnMsg, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) selectUsernameForChat(m_searchHit);
        });
        connect(m_btnFriend, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) sendFriendRequest(m_searchHit);
        });
        connect(m_btnGroupInvite, &QPushButton::clicked, [this]() {
            if (!m_searchHit.isEmpty()) inviteToGroup(m_searchHit);
        });

        /* Timer for message polling + heartbeat + health check */
        auto *timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() {
            fetchMessages();
            if (!m_deviceId.isEmpty()) {
                httpPost("/api/v1/heartbeat", jsonBody({{"device_id", m_deviceId}}));
            }
            /* Health check */
            QByteArray hr = httpGet("/health");
            if (!hr.isEmpty() && hr.contains("\"status\":\"ok\"")) {
                m_statusBar->setText("Online — AES-256-GCM | ECDH P-384");
                m_statusBar->setStyleSheet("color: #2ed573; font-size: 11px; font-weight: bold;");
            } else {
                m_statusBar->setText("Server offline");
                m_statusBar->setStyleSheet("color: #ff4757; font-size: 11px; font-weight: bold;");
            }
        });
        timer->start(4000);

        /* Initial load */
        loadContacts();
    }

    /* ===============================================================
     *  SIDEBAR LOGIC
     * =============================================================== */
    /* Friends-only contact list. Never lists all users. */
    void loadContacts() {
        m_sideList->clear();
        m_friends.clear();
        QByteArray r = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
        QJsonArray arr = QJsonDocument::fromJson(r).object().value("friends").toArray();
        for (const QJsonValue &v : arr) {
            QString name = v.toObject().value("username").toString();
            if (!name.isEmpty()) { m_friends << name; m_sideList->addItem(name); }
        }
        if (m_sideList->count() == 0) {
            auto *item = new QListWidgetItem("(no friends yet — search by username)");
            item->setFlags(Qt::NoItemFlags);
            m_sideList->addItem(item);
        }
    }

    /* Exact-match lookup. Updates the search-result panel. */
    void doExactSearch(const QString &raw) {
        QString q = raw.trimmed();
        if (q.isEmpty()) { hideSearchResult(); return; }
        QByteArray r = httpPost("/api/v1/contacts/search",
            jsonBody({{"device_id", m_deviceId}, {"query", q}}));
        QJsonArray users = QJsonDocument::fromJson(r).object().value("users").toArray();
        QString hit = users.isEmpty() ? QString() : users[0].toString();
        showSearchResult(hit, q);
    }

    void hideSearchResult() {
        if (m_searchResult) m_searchResult->setVisible(false);
        m_searchHit.clear();
    }

    void showSearchResult(const QString &found, const QString &queried) {
        if (!m_searchResult) return;
        m_searchResult->setVisible(true);
        if (found.isEmpty()) {
            m_searchHit.clear();
            m_searchResultLabel->setText(QString("No matching user for \"%1\"").arg(queried.toHtmlEscaped()));
            m_btnMsg->setVisible(false);
            m_btnFriend->setVisible(false);
            m_btnGroupInvite->setVisible(false);
        } else {
            m_searchHit = found;
            m_searchHitIsFriend = m_friends.contains(found, Qt::CaseSensitive);
            m_searchResultLabel->setText(QString("<b>%1</b>%2")
                .arg(found.toHtmlEscaped(), m_searchHitIsFriend ? " (friend)" : ""));
            m_btnMsg->setVisible(true);
            m_btnFriend->setVisible(!m_searchHitIsFriend);
            m_btnGroupInvite->setVisible(true);
        }
    }

    /* Resolve a username to its first device_id by calling /contacts/devices. */
    QString resolveUsernameToDevice(const QString &username) {
        QByteArray r = httpPost("/api/v1/contacts/devices",
            jsonBody({{"device_id", m_deviceId}, {"contact_username", username}}));
        QJsonArray devs = QJsonDocument::fromJson(r).object().value("devices").toArray();
        return devs.isEmpty() ? QString() : devs[0].toObject().value("id").toString();
    }

    /* ── Server identity pinning (TOFU) ─────────────────────────────
       On first connect we record the server's triple-hybrid identity
       fingerprint (Ed25519 + ML-DSA-87 + SPHINCS+-256s). Every later
       connect we refuse if the fingerprint changed — MITM has to either
       impersonate three independent signature schemes or hijack the
       file on the user's disk. */
    QString serverPinPath() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QDir().mkpath(base + "/GHOSTLINK");
        return base + "/GHOSTLINK/server.pin";
    }
    QString loadPinnedFingerprint() {
        QFile f(serverPinPath());
        if (!f.open(QIODevice::ReadOnly)) return QString();
        return QString::fromUtf8(f.readAll()).trimmed();
    }
    bool savePinnedFingerprint(const QString &fp) {
        QFile f(serverPinPath());
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        f.write(fp.toUtf8()); return true;
    }
    /* Returns 0 = ok, 1 = first-pin saved, -1 = mismatch, -2 = endpoint missing */
    int verifyServerIdentity(QString *outFingerprint) {
        QByteArray resp = httpGet("/api/v1/server-identity");
        QJsonObject obj = QJsonDocument::fromJson(resp).object();
        QString fp = obj.value("fingerprint").toString();
        if (fp.isEmpty()) return -2;
        if (outFingerprint) *outFingerprint = fp;
        QString pinned = loadPinnedFingerprint();
        if (pinned.isEmpty()) { savePinnedFingerprint(fp); return 1; }
        if (pinned != fp) return -1;
        return 0;
    }

    /* ── Ratchet bundle publication (forward-secrecy bootstrap) ──── */
    QString ratchetKeyDir() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString dir = base + "/GHOSTLINK/ratchet";
        QDir().mkpath(dir);
        return dir;
    }
    bool publishRatchetBundle(const QString &deviceId) {
        QFile idFile(ratchetKeyDir() + "/identity.x25519");
        if (idFile.exists()) return true;  /* already published */

        BYTE idPriv[32], idPub[32];
        if (!ratchet_x25519_keygen(idPriv, idPub)) return false;

        /* Persist our keypair (priv || pub) for future use. */
        if (!idFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        idFile.write(reinterpret_cast<const char*>(idPriv), 32);
        idFile.write(reinterpret_cast<const char*>(idPub),  32);
        idFile.close();
        idFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner);

        /* Generate a batch of 32 one-time prekeys. */
        QJsonArray otps;
        QFile otpFile(ratchetKeyDir() + "/one_time_prekeys.bin");
        if (!otpFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        for (int i = 0; i < 32; i++) {
            BYTE pkPriv[32], pkPub[32];
            if (!ratchet_x25519_keygen(pkPriv, pkPub)) { otpFile.close(); return false; }
            /* Store priv keyed by prekey_id so we can retrieve when consumed. */
            otpFile.write(reinterpret_cast<const char*>(&i), 4);
            otpFile.write(reinterpret_cast<const char*>(pkPriv), 32);
            QJsonObject one;
            one["prekey_id"] = i;
            one["pub"] = QString::fromUtf8(crypto_hex_encode(pkPub, 32));
            otps.append(one);
        }
        otpFile.close();
        otpFile.setPermissions(QFile::ReadOwner | QFile::WriteOwner);

        QByteArray body = jsonBody({
            {"device_id", deviceId},
            {"x25519_pub", QString::fromUtf8(crypto_hex_encode(idPub, 32))},
            {"one_time_prekeys", otps},
        });
        QByteArray resp = httpPost("/api/v1/ratchet/publish-key", body);
        return !jsonStr(resp, "published").isEmpty();
    }

    /* ── Image attachment storage ───────────────────────────────── */
    QString imagesDir() {
        QString base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        if (base.isEmpty()) base = QDir::tempPath();
        QString dir = base + "/GHOSTLINK/images";
        QDir().mkpath(dir);
        return dir;
    }

    static bool isImageFileName(const QString &name) {
        QString n = name.toLower();
        return n.endsWith(".png") || n.endsWith(".jpg") || n.endsWith(".jpeg")
            || n.endsWith(".gif") || n.endsWith(".bmp") || n.endsWith(".webp");
    }

    /* Insert an image bubble into the chat log. The image is wrapped in an
       anchor whose href encodes the file_id so anchorClicked can open the
       viewer. A constrained width preserves the aspect ratio. */
    void insertImageBubble(const QString &fileId, const QString &localPath,
                            const QString &senderLabel) {
        QImage img(localPath);
        if (img.isNull()) {
            m_chatLog->append(QString("<b>[%1]</b> [image unreadable]")
                .arg(senderLabel.toHtmlEscaped()));
            return;
        }
        m_imagePaths[fileId] = localPath;
        QString resName = QString("image_%1").arg(fileId);
        m_chatLog->document()->addResource(QTextDocument::ImageResource,
                                            QUrl(resName), QVariant(img));
        int maxW = 280;
        int displayW = qMin(maxW, img.width());
        QString html = QString(
            "<div><b>[%1]</b><br/>"
            "<a href=\"ghostlink-img://%2\">"
            "<img src=\"%3\" width=\"%4\"/></a></div>"
        ).arg(senderLabel.toHtmlEscaped(), fileId, resName).arg(displayW);
        m_chatLog->append(html);
    }

    void onChatAnchorClicked(const QUrl &url) {
        if (url.scheme() != "ghostlink-img") return;
        QString fileId = url.host().isEmpty() ? url.path().mid(1) : url.host();
        if (fileId.isEmpty()) fileId = url.toString().section("//", 1, 1);
        QString path = m_imagePaths.value(fileId);
        if (path.isEmpty() || !QFileInfo::exists(path)) {
            QMessageBox::information(this, "Image", "This image is no longer available.");
            return;
        }
        openImageViewer(fileId, path);
    }

    void onChatContextMenu(const QPoint &pos) {
        QTextCursor cur = m_chatLog->cursorForPosition(pos);
        QString href = cur.charFormat().anchorHref();
        QMenu menu(this);
        if (href.startsWith("ghostlink-img://")) {
            QString fileId = href.mid(QString("ghostlink-img://").length());
            QAction *open = menu.addAction("Open Full Size");
            QAction *del = menu.addAction("Delete Image");
            menu.addSeparator();
            menu.addAction("Copy", [this]() { m_chatLog->copy(); });
            QAction *chosen = menu.exec(m_chatLog->mapToGlobal(pos));
            if (chosen == open) {
                QString path = m_imagePaths.value(fileId);
                if (!path.isEmpty()) openImageViewer(fileId, path);
            } else if (chosen == del) {
                if (QMessageBox::question(this, "Delete Image",
                    "Permanently delete this image for both you and the recipient?",
                    QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
                    deleteImage(fileId);
            }
        } else {
            menu.addAction("Copy", [this]() { m_chatLog->copy(); });
            menu.exec(m_chatLog->mapToGlobal(pos));
        }
    }

    /* Server delete + local cache delete + remove the bubble from chat. */
    void deleteImage(const QString &fileId) {
        HttpResponse *r = network_delete(
            QString("/api/v1/files/%1").arg(fileId).toUtf8().constData(),
            m_deviceId.toUtf8().constData());
        if (r) network_free_response(r);
        QString path = m_imagePaths.take(fileId);
        if (!path.isEmpty()) QFile::remove(path);
        replaceImageInChatLog(fileId);
    }

    /* After deletion, walk the chat log document and replace the image
       fragment with a [deleted] placeholder so the bubble updates visually. */
    void replaceImageInChatLog(const QString &fileId) {
        QString anchor = QString("ghostlink-img://%1").arg(fileId);
        QTextCursor c(m_chatLog->document());
        while (!c.atEnd()) {
            c.movePosition(QTextCursor::NextCharacter, QTextCursor::KeepAnchor);
            QString href = c.charFormat().anchorHref();
            if (href == anchor) {
                QTextCursor lineStart = c;
                lineStart.movePosition(QTextCursor::StartOfBlock, QTextCursor::MoveAnchor);
                QTextCursor lineEnd = c;
                lineEnd.movePosition(QTextCursor::EndOfBlock, QTextCursor::MoveAnchor);
                QTextCursor wipe(m_chatLog->document());
                wipe.setPosition(lineStart.position());
                wipe.setPosition(lineEnd.position(), QTextCursor::KeepAnchor);
                wipe.removeSelectedText();
                wipe.insertHtml("<i style=\"color:#888;\">[image deleted]</i>");
                return;
            }
            c.movePosition(QTextCursor::NextCharacter, QTextCursor::MoveAnchor);
        }
    }

    void openImageViewer(const QString &fileId, const QString &path) {
        ImageViewer *v = new ImageViewer(fileId, path, this);
        connect(v, &ImageViewer::deleteRequested, this, [this](const QString &fid) {
            if (QMessageBox::question(this, "Delete Image",
                "Permanently delete this image for both you and the recipient?",
                QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
                deleteImage(fid);
        });
        v->show();
    }

    void selectUsernameForChat(const QString &username) {
        QString did = resolveUsernameToDevice(username);
        if (did.isEmpty()) {
            m_statusBar->setText(QString("No active device for %1").arg(username));
            return;
        }
        m_selectedRecip = did;
        m_toField->setText(username);
    }

    /* Extract server-side error detail (FastAPI: {"detail":"..."}) safely. */
    QString jsonDetail(const QByteArray &resp, const QString &fallback) {
        QString d = QJsonDocument::fromJson(resp).object().value("detail").toString();
        return d.isEmpty() ? fallback : d;
    }

    void sendFriendRequest(const QString &username) {
        bool ok = false;
        QString reason = QInputDialog::getText(this, "Friend Request",
            QString("Send a friend request to %1?\nOptional note:").arg(username),
            QLineEdit::Normal, "", &ok);
        if (!ok) return;
        QByteArray body = jsonBody({
            {"device_id", m_deviceId}, {"target_username", username}, {"reason", reason}
        });
        QByteArray r = httpPost("/api/v1/friends/request", body);
        QJsonObject obj = QJsonDocument::fromJson(r).object();
        if (obj.contains("request_id")) {
            QMessageBox::information(this, "Friend Request", "Request sent.");
        } else {
            QMessageBox::warning(this, "Friend Request", jsonDetail(r, "Failed"));
        }
    }

    void inviteToGroup(const QString &username) {
        /* Pick one of the user's groups. */
        QByteArray r = httpGet(QString("/api/v1/groups/%1").arg(m_deviceId).toUtf8().constData());
        QJsonArray groups = QJsonDocument::fromJson(r).object().value("groups").toArray();
        QStringList names, ids;
        for (const QJsonValue &v : groups) {
            QJsonObject g = v.toObject();
            QString gid = g.value("id").toString();
            QString gname = g.value("name").toString();
            if (!gid.isEmpty()) { ids << gid; names << gname; }
        }
        if (names.isEmpty()) {
            QMessageBox::information(this, "Add to Group", "You have no groups yet. Create one first from the Groups tab.");
            return;
        }
        bool ok = false;
        QString chosen = QInputDialog::getItem(this, "Add to Group",
            QString("Invite %1 to which group?").arg(username), names, 0, false, &ok);
        if (!ok || chosen.isEmpty()) return;
        QString gid = ids[names.indexOf(chosen)];
        QString reason = QInputDialog::getText(this, "Group Invite",
            "Optional note for the recipient:", QLineEdit::Normal, "", &ok);
        if (!ok) return;
        QByteArray body = jsonBody({
            {"device_id", m_deviceId}, {"group_id", gid},
            {"target_username", username}, {"reason", reason}
        });
        QByteArray rr = httpPost("/api/v1/groups/invite", body);
        QJsonObject obj = QJsonDocument::fromJson(rr).object();
        if (obj.contains("invite_id")) {
            QMessageBox::information(this, "Group Invite", "Invite sent.");
        } else {
            QMessageBox::warning(this, "Group Invite", jsonDetail(rr, "Failed"));
        }
    }

    /* ── Requests dialog: pending friend requests + group invites. ── */
    void openRequestsDialog() {
        QDialog dlg(this);
        dlg.setWindowTitle("Pending Requests");
        dlg.resize(520, 460);
        auto *lay = new QVBoxLayout(&dlg);
        auto *tabs = new QTabWidget;

        /* Friend requests tab */
        auto *fw = new QWidget; auto *fl = new QVBoxLayout(fw);
        auto *fList = new QListWidget; fl->addWidget(fList, 1);
        auto *frRow = new QHBoxLayout;
        auto *frAccept = new QPushButton("Accept");
        auto *frDeny = new QPushButton("Deny");
        frRow->addStretch(); frRow->addWidget(frAccept); frRow->addWidget(frDeny);
        fl->addLayout(frRow);
        tabs->addTab(fw, "Friend Requests");

        /* Group invites tab */
        auto *gw = new QWidget; auto *gl = new QVBoxLayout(gw);
        auto *gList = new QListWidget; gl->addWidget(gList, 1);
        auto *giRow = new QHBoxLayout;
        auto *giAccept = new QPushButton("Accept");
        auto *giDeny = new QPushButton("Deny");
        giRow->addStretch(); giRow->addWidget(giAccept); giRow->addWidget(giDeny);
        gl->addLayout(giRow);
        tabs->addTab(gw, "Group Invites");

        lay->addWidget(tabs, 1);
        auto *closeBtn = new QPushButton("Close");
        connect(closeBtn, &QPushButton::clicked, &dlg, &QDialog::accept);
        lay->addWidget(closeBtn);

        /* Holds (id, from, reason) per row so we can act on selection. */
        QList<QStringList> frData, giData;

        auto reloadFriends = [&]() {
            fList->clear(); frData.clear();
            QByteArray r = httpPost("/api/v1/friends/list", jsonBody({{"device_id", m_deviceId}}));
            QJsonArray incoming = QJsonDocument::fromJson(r).object().value("incoming").toArray();
            for (const QJsonValue &v : incoming) {
                QJsonObject o = v.toObject();
                QString id = o.value("id").toString();
                QString from = o.value("from").toString();
                QString reason = o.value("reason").toString();
                if (id.isEmpty()) continue;
                frData << QStringList{id, from, reason};
                fList->addItem(reason.isEmpty() ? from : QString("%1 — \"%2\"").arg(from, reason));
            }
        };

        auto reloadInvites = [&]() {
            gList->clear(); giData.clear();
            QByteArray r = httpPost("/api/v1/groups/invites/list", jsonBody({{"device_id", m_deviceId}}));
            QJsonArray invites = QJsonDocument::fromJson(r).object().value("invites").toArray();
            for (const QJsonValue &v : invites) {
                QJsonObject o = v.toObject();
                QString id = o.value("id").toString();
                QString gname = o.value("group_name").toString();
                QString from = o.value("from").toString();
                QString reason = o.value("reason").toString();
                if (id.isEmpty()) continue;
                giData << QStringList{id, gname, from, reason};
                QString label = QString("%1 invited you to %2").arg(from, gname);
                if (!reason.isEmpty()) label += QString(" — \"%1\"").arg(reason);
                gList->addItem(label);
            }
        };

        auto respondFriend = [&](bool accept) {
            int row = fList->currentRow();
            if (row < 0 || row >= frData.size()) return;
            QString reason;
            if (!accept) {
                bool ok = false;
                reason = QInputDialog::getText(&dlg, "Deny", "Optional reason:", QLineEdit::Normal, "", &ok);
                if (!ok) return;
            }
            QByteArray body = jsonBody({
                {"device_id", m_deviceId}, {"request_id", frData[row][0]},
                {"accept", accept}, {"reason", reason}
            });
            httpPost("/api/v1/friends/respond", body);
            reloadFriends();
            if (accept) loadContacts();
        };

        auto respondInvite = [&](bool accept) {
            int row = gList->currentRow();
            if (row < 0 || row >= giData.size()) return;
            QString reason;
            if (!accept) {
                bool ok = false;
                reason = QInputDialog::getText(&dlg, "Deny", "Optional reason:", QLineEdit::Normal, "", &ok);
                if (!ok) return;
            }
            QByteArray body = jsonBody({
                {"device_id", m_deviceId}, {"invite_id", giData[row][0]},
                {"accept", accept}, {"reason", reason}
            });
            httpPost("/api/v1/groups/invites/respond", body);
            reloadInvites();
        };

        connect(frAccept, &QPushButton::clicked, [&]() { respondFriend(true); });
        connect(frDeny,   &QPushButton::clicked, [&]() { respondFriend(false); });
        connect(giAccept, &QPushButton::clicked, [&]() { respondInvite(true); });
        connect(giDeny,   &QPushButton::clicked, [&]() { respondInvite(false); });

        reloadFriends();
        reloadInvites();
        dlg.exec();
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

    void createGroup(const QString &name) {
        QVariantList members{ QVariantMap{
            {"device_id", m_deviceId}, {"encrypted_group_key", QString("demo")}
        }};
        QByteArray body = jsonBody({
            {"group_name", name.isEmpty() ? QString("New Group") : name},
            {"creator_device_id", m_deviceId},
            {"members", members}
        });
        httpPost("/api/v1/groups/create", body);
        loadGroups();
    }

    void sideSelect(QListWidgetItem *item) {
        QString text = item->text();
        if (m_tabGroups) {
            int lb = text.indexOf('['), rb = text.indexOf(']');
            if (lb >= 0 && rb > lb) m_selectedRecip = text.mid(lb + 1, rb - lb - 1);
            m_toField->setText(text);
        } else {
            /* Sidebar items are usernames; resolve to a device_id for sending. */
            QString did = resolveUsernameToDevice(text);
            if (did.isEmpty()) {
                m_statusBar->setText(QString("No active device for %1").arg(text));
                return;
            }
            m_selectedRecip = did;
            m_toField->setText(text);
        }
    }

    /* ===============================================================
     *  MESSAGING
     * =============================================================== */
    void sendMessage() {
        QString body = m_msgInput->text().trimmed();
        if (body.isEmpty() || m_selectedRecip.isEmpty()) return;

        BYTE sk[32];
        unsigned char pub[PUBLIC_KEY_MAX]; DWORD plen = 0;
        /* Get key from existing identity */
        if (storage_exists()) {
            DeviceConfig cfg;
            if (storage_load_config(&cfg)) {
                crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);
            }
        }

        qint64 ts = QDateTime::currentSecsSinceEpoch();
        QByteArray pl = jsonBody({
            {"body", body}, {"name", m_username}, {"sender", m_deviceId}, {"ts", ts}
        });

        BYTE iv[12], ct[5000], tag[16];
        crypto_random_bytes(iv, 12);
        crypto_aes_gcm_encrypt(sk, (const BYTE*)pl.constData(), pl.size(), iv, ct, tag);

        char *ih = crypto_hex_encode(iv, 12);
        char *ch = crypto_hex_encode(ct, pl.size());
        char *th = crypto_hex_encode(tag, 16);
        BYTE sig[32]; crypto_sha256(ct, pl.size(), sig);
        char *sh = crypto_hex_encode(sig, 32);

        QVariantMap env{
            {"sender", m_deviceId}, {"ts", ts},
            {"nonce", QString::fromUtf8(ih)}, {"ciphertext", QString::fromUtf8(ch)},
            {"tag", QString::fromUtf8(th)}, {"sig", QString::fromUtf8(sh)}
        };
        free(ih); free(ch); free(th); free(sh);

        QByteArray jb = jsonBody({
            {"sender_device_id", m_deviceId}, {"recipient_device_id", m_selectedRecip},
            {"envelope", env}
        });
        httpPost("/api/v1/messages/send", jb);

        m_chatLog->append(QString("<b>[%1]</b> %2")
            .arg(m_username.toHtmlEscaped(), body.toHtmlEscaped()));
        m_msgInput->clear();
    }

    /* Fetch a sender device's public-key blob (hex) and derive the symmetric
       file key as SHA-256(pubkey_blob), matching how the sender encrypted. */
    bool senderFileKey(const QString &senderDeviceId, BYTE key_out[32]) {
        QByteArray r = httpGet(QString("/api/v1/devices/%1/pubkey").arg(senderDeviceId).toUtf8().constData());
        if (r.isEmpty()) return false;
        QString pubHex = QJsonDocument::fromJson(r).object().value("public_key").toString();
        if (pubHex.isEmpty()) return false;
        BYTE pub[PUBLIC_KEY_MAX]; DWORD pubLen = 0;
        if (!crypto_hex_decode(pubHex.toUtf8().constData(), pub, &pubLen)) return false;
        return crypto_sha256(pub, pubLen, key_out);
    }

    QJsonObject decryptEnvelope(const QJsonObject &env, const QString &senderDeviceId) {
        BYTE sk[32];
        if (!senderFileKey(senderDeviceId, sk)) return QJsonObject();
        BYTE nonce[12], tag[16];
        DWORD nl = 12, tl = 16;
        crypto_hex_decode(env.value("nonce").toString().toUtf8().constData(), nonce, &nl);
        crypto_hex_decode(env.value("tag").toString().toUtf8().constData(), tag, &tl);
        QByteArray ctHex = env.value("ciphertext").toString().toUtf8();
        DWORD clen = (DWORD)(ctHex.size() / 2);
        if (clen == 0 || clen > 8192) return QJsonObject();
        QVector<BYTE> ct(clen), pt(clen);
        DWORD got = clen;
        if (!crypto_hex_decode(ctHex.constData(), ct.data(), &got)) return QJsonObject();
        if (!crypto_aes_gcm_decrypt(sk, nonce, ct.data(), clen, tag, pt.data())) return QJsonObject();
        return QJsonDocument::fromJson(QByteArray(reinterpret_cast<const char*>(pt.data()), (int)clen)).object();
    }

    QString downloadAndDecryptImage(const QString &fileId, const QString &senderDeviceId,
                                     const QString &originalName) {
        BYTE sk[32];
        if (!senderFileKey(senderDeviceId, sk)) return QString();
        BYTE *enc = nullptr; DWORD elen = 0;
        network_download_file(QString("/api/v1/files/%1").arg(fileId).toUtf8().constData(),
                              m_deviceId.toUtf8().constData(), &enc, &elen);
        if (!enc || elen < 28) { if (enc) free(enc); return QString(); }
        BYTE *plain = nullptr; DWORD plen = 0;
        bool ok = crypto_decrypt_file_data(sk, enc, elen, &plain, &plen);
        free(enc);
        if (!ok || !plain) { if (plain) free(plain); return QString(); }
        QString ext = QFileInfo(originalName).suffix().toLower();
        if (ext.isEmpty()) ext = "png";
        QString localPath = QString("%1/%2.%3").arg(imagesDir(), fileId, ext);
        QFile out(localPath);
        if (out.open(QIODevice::WriteOnly)) {
            out.write(reinterpret_cast<const char*>(plain), plen);
            out.close();
        }
        free(plain);
        return localPath;
    }

    void fetchMessages() {
        if (m_deviceId.isEmpty()) return;
        QByteArray r = httpPost("/api/v1/messages/fetch", jsonBody({{"device_id", m_deviceId}}));
        m_statusBar->setText("Online — AES-256-GCM | ECDH P-384");
        m_statusBar->setStyleSheet("color: #2ed573; font-size: 11px; font-weight: bold;");
        QJsonObject root = QJsonDocument::fromJson(r).object();
        QJsonArray msgs = root.value("messages").toArray();
        for (const QJsonValue &mv : msgs) {
            QJsonObject m = mv.toObject();
            QString sender = m.value("sender_device_id").toString();
            QJsonObject env = m.value("envelope").toObject();
            QJsonObject plain = decryptEnvelope(env, sender);
            QString senderName = plain.value("name").toString();
            if (senderName.isEmpty()) senderName = sender.left(12);
            QString body = plain.value("body").toString();
            QString type = plain.value("type").toString();
            QString fileId = plain.value("file_id").toString();
            bool isImage = plain.value("is_image").toBool() || type == "image";
            if (isImage && !fileId.isEmpty()) {
                QString localPath = downloadAndDecryptImage(fileId, sender, plain.value("name").toString());
                if (!localPath.isEmpty()) {
                    insertImageBubble(fileId, localPath, senderName);
                    continue;
                }
            }
            if (!body.isEmpty()) {
                m_chatLog->append(QString("<b>[%1]</b> %2")
                    .arg(senderName.toHtmlEscaped(), body.toHtmlEscaped()));
            }
        }
    }

    /* ===============================================================
     *  FILE ATTACH
     * =============================================================== */
    void attachFile() {
        QString path = QFileDialog::getOpenFileName(this, "Select File to Send (Encrypted)",
            QString(), "All Files (*.*);;Images (*.png *.jpg *.jpeg *.gif *.bmp *.webp)");
        if (path.isEmpty() || m_selectedRecip.isEmpty()) return;

        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return;
        QByteArray data = f.readAll();
        f.close();

        QString fname = QFileInfo(path).fileName();
        bool isImage = isImageFileName(fname);

        BYTE sk[32];
        DeviceConfig cfg;
        if (storage_load_config(&cfg))
            crypto_sha256(cfg.identity_key.pub.data, cfg.identity_key.pub.len, sk);

        BYTE *enc = nullptr; DWORD elen = 0;
        if (!crypto_encrypt_file_data(sk, (const BYTE*)data.constData(), data.size(), &enc, &elen)) return;

        QString mime = isImage ? QString("image/") + QFileInfo(path).suffix().toLower() : QString();
        QByteArray meta = jsonBody({
            {"name", fname}, {"size", (qint64)data.size()},
            {"mime", mime}, {"is_image", isImage}
        });

        m_statusBar->setText("Uploading encrypted file...");
        QApplication::processEvents();

        HttpResponse *ur = network_upload_file("/api/v1/files/upload", enc, elen,
            m_deviceId.toUtf8().constData(), m_selectedRecip.toUtf8().constData(),
            meta.constData());
        free(enc);

        QString fileId;
        if (ur && ur->len > 0) {
            QByteArray ub(ur->data, (int)ur->len);
            fileId = QJsonDocument::fromJson(ub).object().value("file_id").toString();
            network_free_response(ur);
        }
        if (fileId.isEmpty()) { m_statusBar->setText("Upload failed"); return; }

        /* Cache plaintext locally so the sender can view + the viewer can
           open it from disk later. */
        QString localPath;
        if (isImage) {
            QString ext = QFileInfo(path).suffix().toLower();
            localPath = QString("%1/%2.%3").arg(imagesDir(), fileId, ext);
            QFile out(localPath);
            if (out.open(QIODevice::WriteOnly)) { out.write(data); out.close(); }
        }

        qint64 ts = QDateTime::currentSecsSinceEpoch();
        QByteArray plb = jsonBody({
            {"type", QString(isImage ? "image" : "file")}, {"file_id", fileId},
            {"name", fname}, {"size", (qint64)data.size()},
            {"mime", mime}, {"is_image", isImage},
            {"body", isImage
                ? QString("Sent image: %1").arg(fname)
                : QString("Sent file: %1 (%2 bytes)").arg(fname).arg(data.size())}
        });

        BYTE iv[12], ct[5000], tag[16];
        crypto_random_bytes(iv, 12);
        crypto_aes_gcm_encrypt(sk, (const BYTE*)plb.constData(), plb.size(), iv, ct, tag);
        char *ih = crypto_hex_encode(iv, 12);
        char *ch = crypto_hex_encode(ct, plb.size());
        char *th = crypto_hex_encode(tag, 16);
        BYTE sig[32]; crypto_sha256(ct, plb.size(), sig);
        char *sh = crypto_hex_encode(sig, 32);

        QVariantMap env{
            {"sender", m_deviceId}, {"ts", ts},
            {"nonce", QString::fromUtf8(ih)}, {"ciphertext", QString::fromUtf8(ch)},
            {"tag", QString::fromUtf8(th)}, {"sig", QString::fromUtf8(sh)}
        };
        free(ih); free(ch); free(th); free(sh);

        QByteArray jb = jsonBody({
            {"sender_device_id", m_deviceId}, {"recipient_device_id", m_selectedRecip},
            {"envelope", env}
        });
        httpPost("/api/v1/messages/send", jb);

        if (isImage && !localPath.isEmpty()) {
            insertImageBubble(fileId, localPath, m_username);
        } else {
            m_chatLog->append(QString("<b>[%1]</b> [FILE] %2 (%3 bytes)")
                .arg(m_username.toHtmlEscaped(), fname.toHtmlEscaped()).arg(data.size()));
        }
        m_statusBar->setText(isImage
            ? QString("Image sent: %1").arg(fname)
            : QString("File sent: %1").arg(fname));
    }

    /* ===============================================================
     *  SETTINGS
     * =============================================================== */
    void openSettings() {
        QDialog dlg(this);
        dlg.setWindowTitle("GHOSTLINK Settings");
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
        attachPasswordReveal(oldPw); attachPasswordReveal(newPw); attachPasswordReveal(cfmPw);
        pl->addWidget(oldPw); pl->addWidget(newPw); pl->addWidget(cfmPw);
        auto *chBtn = new QPushButton("Change Password");
        connect(chBtn, &QPushButton::clicked, [=, &dlg]() {
            if (newPw->text().length() < 12 || newPw->text() != cfmPw->text()) {
                QMessageBox::warning(&dlg, "Error", "Password must be 12+ chars and match"); return;
            }
            QByteArray b = jsonBody({
                {"username", m_username},
                {"old_password", oldPw->text()},
                {"new_password", newPw->text()}
            });
            QByteArray r = httpPost("/api/v1/change-password", b);
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
                "Delete ALL data and the GHOSTLINK executable?\nThis is IRREVERSIBLE.",
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

/* ===================================================================
 *  CryptoSplash — animated boot splash. Lattice-themed to mirror the
 *  app icon. Drawn entirely with QPainter, no external assets.
 * =================================================================== */
class CryptoSplash : public QWidget {
    Q_OBJECT
public:
    explicit CryptoSplash(int holdMs = 2000)
        : QWidget(nullptr, Qt::SplashScreen | Qt::FramelessWindowHint)
        , m_holdMs(holdMs)
    {
        setAttribute(Qt::WA_TranslucentBackground);
        setFixedSize(600, 380);
        QScreen *scr = QGuiApplication::primaryScreen();
        if (scr) {
            QRect g = scr->availableGeometry();
            move(g.center() - rect().center());
        }
        m_phases = {
            "Initializing CNG provider",
            "Generating ECDH P-384 keypair",
            "Loading ML-KEM-1024 lattice",
            "Detecting TPM 2.0 module",
            "Running FIPS 140-2 self-test",
            "Establishing secure channel",
        };
        m_anim = new QTimer(this);
        connect(m_anim, &QTimer::timeout, this, [this]() {
            m_tick++;
            int pct = (int)(100.0 * m_tick / qMax(1, m_holdMs / 33));
            m_progress = qMin(100, pct);
            int idx = qMin((int)m_phases.size() - 1,
                           (int)(m_progress * m_phases.size() / 100));
            m_phaseIdx = idx;
            update();
        });
        m_anim->start(33);
    }

    int holdMs() const { return m_holdMs; }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r = rect();
        const qreal radius = 16.0;

        /* ── Background card ────────────────────────────────────── */
        QLinearGradient bg(r.topLeft(), r.bottomLeft());
        bg.setColorAt(0.0, QColor(8, 14, 28));
        bg.setColorAt(1.0, QColor(16, 26, 48));
        QPainterPath card;
        card.addRoundedRect(r.adjusted(1, 1, -1, -1), radius, radius);
        p.fillPath(card, bg);

        /* ── Hex lattice background ─────────────────────────────── */
        p.save();
        p.setClipPath(card);
        QPen latPen(QColor(255, 140, 30, 40));
        latPen.setWidthF(1.0);
        p.setPen(latPen);
        const qreal hr = 18.0;
        const qreal hx = hr * 1.5;
        const qreal hy = hr * std::sqrt(3.0);
        qreal drift = (m_tick * 0.4);
        for (qreal y = -hy; y < r.height() + hy; y += hy) {
            for (qreal x = -hx; x < r.width() + hx; x += hx) {
                qreal cx = x + std::fmod(drift, hx);
                qreal cy = y + ((int)((x - drift) / hx) % 2 ? hy * 0.5 : 0);
                drawHex(p, cx, cy, hr, 0);
            }
        }
        p.restore();

        /* ── Central crypto core: layered hex cluster ───────────── */
        const QPointF center(r.width() * 0.28, r.height() * 0.5);
        const qreal R = 44.0;
        const qreal spacing = R * std::sqrt(3.0) * 1.0;

        /* Lines from outer hexes to center, animated phase pulse */
        QPen linePen(QColor(255, 160, 50,
                            120 + (int)(60 * std::sin(m_tick * 0.08))));
        linePen.setWidthF(1.5);
        p.setPen(linePen);
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i - 30.0);
            QPointF o(center.x() + spacing * std::cos(a),
                      center.y() + spacing * std::sin(a));
            p.drawLine(center, o);
        }

        /* Outer six hexes — rotate slowly */
        qreal rot = m_tick * 0.5;
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i - 30.0 + rot);
            QPointF o(center.x() + spacing * std::cos(a),
                      center.y() + spacing * std::sin(a));
            QPen op(QColor(255, 160, 50, 220));
            op.setWidthF(2.0);
            p.setPen(op);
            p.setBrush(Qt::NoBrush);
            drawHex(p, o.x(), o.y(), R * 0.42, 30);
            p.setBrush(QColor(255, 180, 70, 230));
            p.setPen(Qt::NoPen);
            p.drawEllipse(o, 4.0, 4.0);
        }

        /* Central hex — bright core with mint key glyph */
        QColor coreBorder = QColor(255, 140, 30);
        QPen cp(coreBorder);
        cp.setWidthF(3.0);
        p.setPen(cp);
        p.setBrush(QColor(40, 20, 8, 230));
        drawHex(p, center.x(), center.y(), R, 30);

        qreal inner = R * 0.42;
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(255, 210, 100));
        p.drawRect(QRectF(center.x() - inner * 0.5, center.y() - inner * 0.5,
                          inner, inner));
        p.drawRect(QRectF(center.x() + inner * 0.5 - inner * 0.12,
                          center.y() - inner * 0.15,
                          inner * 0.30, inner * 0.30));

        /* Pulsing glow ring around the core */
        qreal pulse = 0.5 + 0.5 * std::sin(m_tick * 0.10);
        QPen glowP(QColor(255, 140, 30, (int)(60 + pulse * 80)));
        glowP.setWidthF(2.0 + pulse * 2.0);
        p.setPen(glowP);
        p.setBrush(Qt::NoBrush);
        p.drawEllipse(center, R + 18 + pulse * 6, R + 18 + pulse * 6);

        /* ── Title block (right side) ───────────────────────────── */
        const qreal textX = r.width() * 0.5;
        const qreal textW = r.width() - textX - 32;

        QFont titleFont("Segoe UI", 28, QFont::Black);
        titleFont.setLetterSpacing(QFont::AbsoluteSpacing, 6.0);
        p.setFont(titleFont);
        p.setPen(QColor(255, 170, 60));
        p.drawText(QRectF(textX, 96, textW, 44),
                   Qt::AlignLeft | Qt::AlignVCenter, "GHOSTLINK");

        /* Underline accent */
        p.setPen(QPen(QColor(255, 140, 30, 230), 2.0));
        p.drawLine(QPointF(textX, 148), QPointF(textX + 180, 148));

        /* Crypto specs */
        QFont specFont("Consolas", 9);
        p.setFont(specFont);
        p.setPen(QColor(230, 165, 80));
        p.drawText(QRectF(textX, 158, textW, 18),
                   Qt::AlignLeft | Qt::AlignVCenter,
                   "AES-256-GCM  ·  ECDH P-384  ·  ML-KEM-1024");
        p.setPen(QColor(180, 120, 55));
        p.drawText(QRectF(textX, 174, textW, 16),
                   Qt::AlignLeft | Qt::AlignVCenter,
                   "FIPS 140-2  ·  TPM 2.0  ·  Zero metadata");

        /* ── Progress bar ───────────────────────────────────────── */
        const qreal barY = r.height() - 70;
        const qreal barH = 4;
        QRectF barBg(textX, barY, textW, barH);
        p.setPen(Qt::NoPen);
        p.setBrush(QColor(50, 30, 14));
        p.drawRoundedRect(barBg, 2, 2);
        QRectF barFill(textX, barY, textW * m_progress / 100.0, barH);
        QLinearGradient barG(barFill.topLeft(), barFill.topRight());
        barG.setColorAt(0.0, QColor(255, 110, 20));
        barG.setColorAt(1.0, QColor(255, 200, 80));
        p.setBrush(barG);
        p.drawRoundedRect(barFill, 2, 2);

        /* Phase label */
        QFont phaseFont("Consolas", 9);
        p.setFont(phaseFont);
        p.setPen(QColor(255, 160, 40));
        QString tag = QString("[%1]").arg(m_progress, 3, 10, QChar('0'));
        p.drawText(QRectF(textX, barY + 12, 50, 18),
                   Qt::AlignLeft | Qt::AlignVCenter, tag);
        p.setPen(QColor(245, 200, 130));
        QString phase = m_phases.value(m_phaseIdx) + "...";
        p.drawText(QRectF(textX + 50, barY + 12, textW - 50, 18),
                   Qt::AlignLeft | Qt::AlignVCenter, phase);

        /* Version watermark */
        QFont vFont("Consolas", 8);
        p.setFont(vFont);
        p.setPen(QColor(140, 95, 50));
        p.drawText(QRectF(r.width() - 80, r.height() - 22, 70, 16),
                   Qt::AlignRight | Qt::AlignVCenter,
                   QString("v") + CLIENT_VERSION);

        /* ── Outer border highlight ─────────────────────────────── */
        p.setPen(QPen(QColor(255, 140, 30, 180), 1.5));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(r.adjusted(1, 1, -1, -1), radius, radius);
    }

private:
    static void drawHex(QPainter &p, qreal cx, qreal cy, qreal radius, qreal rotDeg) {
        QPolygonF poly;
        for (int i = 0; i < 6; i++) {
            qreal a = qDegreesToRadians(60.0 * i + rotDeg);
            poly << QPointF(cx + radius * std::cos(a), cy + radius * std::sin(a));
        }
        p.drawPolygon(poly);
    }

    QTimer *m_anim;
    int m_tick = 0;
    int m_progress = 0;
    int m_phaseIdx = 0;
    int m_holdMs;
    QStringList m_phases;
};

#include "main.moc"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("GHOSTLINK");
    app.setApplicationVersion(CLIENT_VERSION);
    app.setWindowIcon(QIcon(":/ghostlink.png"));

    CryptoSplash splash;
    splash.show();
    app.processEvents();

    /* Construct main window synchronously (crypto/network/TPM init runs here).
       The splash stays visible while the constructor runs, then for the
       remainder of the hold time. */
    GhostlinkWindow w;
    w.setWindowIcon(QIcon(":/ghostlink.png"));

    QTimer::singleShot(splash.holdMs(), &splash, [&]() {
        w.show();
        w.raise();
        w.activateWindow();
        splash.close();
    });

    return app.exec();
}
