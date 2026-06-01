#include "admin_client.h"
#include <QSslConfiguration>
#include <QtNetwork/QNetworkCookie>
#include <QtNetwork/QNetworkProxy>
#include <QUrlQuery>
#include <QSysInfo>
#include <QJsonArray>
#include "oauth_helper.h"

AdminClient::AdminClient(QObject *parent) : QObject(parent) {
    QSettings s("SHROUD", "admin");
    m_relayUrl       = s.value("relay_url", "https://44.202.225.57:58443").toString();
    m_anthropicKey   = s.value("anthropic_key", "").toString();
    m_sessionCookie  = s.value("admin_session", "").toString();
    m_socksProxy     = s.value("socks_proxy", "").toString();
    m_csrfToken      = s.value("csrf_token", "").toString();
    applyProxy();

    // Schannel (Qt's default TLS backend on Windows) ignores the
    // per-request setPeerVerifyMode(VerifyNone) in some failure modes,
    // surfacing as "SSL handshake failed: An internal token was invalid"
    // (SEC_E_INVALID_TOKEN) against any self-signed relay. Catch every
    // reply's sslErrors signal at the NAM level and ignore them. The
    // wire-security model never depended on the TLS chain anyway —
    // every auth / message payload is encrypted at the application
    // layer regardless of transport.
    connect(&m_nam, &QNetworkAccessManager::sslErrors,
            this, [this](QNetworkReply *reply, const QList<QSslError> &) {
                if (m_acceptSelfSigned) reply->ignoreSslErrors();
            });

#ifdef SHROUD_ADMIN_HAS_WS
    connect(&m_ws, &QWebSocket::connected,         this, &AdminClient::onWsConnected);
    connect(&m_ws, &QWebSocket::disconnected,      this, &AdminClient::onWsDisconnected);
    connect(&m_ws, &QWebSocket::textMessageReceived, this, &AdminClient::onWsTextMessage);
    connect(&m_ws, QOverload<const QList<QSslError> &>::of(&QWebSocket::sslErrors),
            this, [this](const QList<QSslError> &) {
                if (m_acceptSelfSigned) m_ws.ignoreSslErrors();
            });
#endif
}

void AdminClient::setSocksProxy(const QString &hostPort) {
    m_socksProxy = hostPort.trimmed();
    QSettings("SHROUD", "admin").setValue("socks_proxy", m_socksProxy);
    applyProxy();
}

void AdminClient::applyProxy() {
    QNetworkProxy proxy;
    if (m_socksProxy.isEmpty()) {
        proxy.setType(QNetworkProxy::NoProxy);
    } else {
        QStringList parts = m_socksProxy.split(':');
        if (parts.size() != 2) {
            proxy.setType(QNetworkProxy::NoProxy);
        } else {
            proxy.setType(QNetworkProxy::Socks5Proxy);
            proxy.setHostName(parts[0]);
            proxy.setPort(parts[1].toUShort());
        }
    }
    m_nam.setProxy(proxy);
#ifdef SHROUD_ADMIN_HAS_WS
    m_ws.setProxy(proxy);
#endif
}

void AdminClient::adminLogin(const QString &fingerprintId, const QString &password,
                             std::function<void(bool, const QString &)> cb) {
    QJsonObject body;
    body["fingerprint_id"] = fingerprintId;
    body["password"]       = password;
    body["hwid"]           = QString::fromUtf8(QSysInfo::machineUniqueId().toBase64());
    QNetworkRequest req = buildReq(
        m_relayUrl + "/api/v1/admin/fingerprint-login", "application/json");
    QNetworkReply *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    QObject::connect(r, &QNetworkReply::finished, [this, r, fingerprintId, cb]() {
        if (r->error() != QNetworkReply::NoError) {
            QString detail = QString::fromUtf8(r->readAll());
            r->deleteLater();
            cb(false, detail.isEmpty() ? r->errorString() : detail);
            return;
        }
        // Server sets BOTH shroud_sid (httpOnly session) AND shroud_csrf
        // (JS-readable CSRF token). We must capture both — every write
        // endpoint requires X-CSRF-Token to match the cookie value.
        auto cookies = qvariant_cast<QList<QNetworkCookie>>(
            r->header(QNetworkRequest::SetCookieHeader));
        for (const auto &c : cookies) {
            if (c.name() == "shroud_sid") {
                setAdminSessionCookie(QString::fromUtf8(c.value()));
            } else if (c.name() == "shroud_csrf") {
                setCsrfToken(QString::fromUtf8(c.value()));
            }
        }
        setSavedFingerprint(fingerprintId);
        r->deleteLater();
        connectAdminWs();
        cb(true, "");
    });
}

void AdminClient::adminFirstTimeSetup(
        std::function<void(const QString &fp, const QString &err)> cb) {
    QNetworkRequest req = buildReq(
        m_relayUrl + "/api/v1/admin/setup", "application/json");
    QNetworkReply *r = m_nam.post(req, "{}");
    QObject::connect(r, &QNetworkReply::finished, [this, r, cb]() {
        QString detail = QString::fromUtf8(r->readAll());
        int http = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        r->deleteLater();
        if (http == 200) {
            // Body shape: { ok, fingerprint_id, note }
            QJsonDocument d = QJsonDocument::fromJson(detail.toUtf8());
            QString fp = d.object().value("fingerprint_id").toString();
            setSavedFingerprint(fp);
            cb(fp, "");
        } else {
            cb("", detail.isEmpty() ? QString("HTTP %1").arg(http) : detail);
        }
    });
}

void AdminClient::adminLogout(std::function<void(bool)> cb) {
    postJson("/api/v1/admin/logout", QJsonObject(),
             [this, cb](const QJsonDocument &, const QString &err) {
        setAdminSessionCookie("");
        setCsrfToken("");
        disconnectAdminWs();
        cb(err.isEmpty());
    });
}

void AdminClient::setCsrfToken(const QString &t) {
    m_csrfToken = t;
    QSettings("SHROUD", "admin").setValue("csrf_token", t);
}

QString AdminClient::savedFingerprint() const {
    return QSettings("SHROUD", "admin").value("admin_fingerprint", "").toString();
}

void AdminClient::setSavedFingerprint(const QString &fp) {
    QSettings("SHROUD", "admin").setValue("admin_fingerprint", fp);
}

void AdminClient::setRelayUrl(const QString &url) {
    m_relayUrl = url;
    QSettings("SHROUD", "admin").setValue("relay_url", url);
}

void AdminClient::setAdminSessionCookie(const QString &cookie) {
    m_sessionCookie = cookie;
    QSettings("SHROUD", "admin").setValue("admin_session", cookie);
}

void AdminClient::setAnthropicKey(const QString &k) {
    m_anthropicKey = k;
    QSettings("SHROUD", "admin").setValue("anthropic_key", k);
}

QNetworkRequest AdminClient::buildReq(const QString &fullUrl, const QString &contentType) {
    QNetworkRequest req((QUrl(fullUrl)));
    if (!contentType.isEmpty()) {
        req.setHeader(QNetworkRequest::ContentTypeHeader, contentType);
    }
    if (!m_sessionCookie.isEmpty()) {
        // Two cookies, both required: shroud_sid is the httpOnly session
        // anchor, shroud_csrf is the double-submit token the server
        // matches against the X-CSRF-Token header on every write.
        QString cookieHdr = QString("shroud_sid=%1").arg(m_sessionCookie);
        if (!m_csrfToken.isEmpty()) {
            cookieHdr += QString("; shroud_csrf=%1").arg(m_csrfToken);
            req.setRawHeader("X-CSRF-Token", m_csrfToken.toUtf8());
        }
        req.setRawHeader("Cookie", cookieHdr.toUtf8());
    }
    // Accept self-signed relay certs.
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    req.setSslConfiguration(cfg);
    return req;
}

static void replyToCb(QNetworkReply *reply,
                      std::function<void(const QJsonDocument &, const QString &)> cb) {
    QObject::connect(reply, &QNetworkReply::finished, [reply, cb]() {
        QString err;
        QJsonDocument doc;
        if (reply->error() != QNetworkReply::NoError) {
            err = reply->errorString();
        }
        const auto body = reply->readAll();
        if (!body.isEmpty()) {
            QJsonParseError pe;
            doc = QJsonDocument::fromJson(body, &pe);
            if (pe.error != QJsonParseError::NoError && err.isEmpty()) {
                err = QString("parse error: %1").arg(pe.errorString());
            }
        }
        reply->deleteLater();
        cb(doc, err);
    });
}

void AdminClient::getJson(const QString &path,
                          std::function<void(const QJsonDocument &, const QString &)> cb) {
    QNetworkRequest req = buildReq(m_relayUrl + path);
    QNetworkReply *r = m_nam.get(req);
    replyToCb(r, cb);
}

void AdminClient::postJson(const QString &path, const QJsonObject &body,
                           std::function<void(const QJsonDocument &, const QString &)> cb) {
    QNetworkRequest req = buildReq(m_relayUrl + path, "application/json");
    QNetworkReply *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    replyToCb(r, cb);
}

void AdminClient::deleteRequest(const QString &path,
                                std::function<void(const QJsonDocument &, const QString &)> cb) {
    QNetworkRequest req = buildReq(m_relayUrl + path);
    QNetworkReply *r = m_nam.deleteResource(req);
    replyToCb(r, cb);
}

void AdminClient::connectAdminWs() {
#ifdef SHROUD_ADMIN_HAS_WS
    if (m_ws.state() == QAbstractSocket::ConnectedState) return;
    QString ws = m_relayUrl;
    if (ws.startsWith("https://")) ws.replace(0, 8, "wss://");
    else if (ws.startsWith("http://")) ws.replace(0, 7, "ws://");
    ws += "/ws/admin";
    QNetworkRequest req((QUrl(ws)));
    if (!m_sessionCookie.isEmpty()) {
        req.setRawHeader("Cookie", QString("shroud_sid=%1").arg(m_sessionCookie).toUtf8());
    }
    QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
    cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
    m_ws.setSslConfiguration(cfg);
    m_ws.open(req);
#endif
}

void AdminClient::disconnectAdminWs() {
#ifdef SHROUD_ADMIN_HAS_WS
    m_ws.close();
#endif
}

void AdminClient::onWsConnected()    { emit wsConnected(); }
void AdminClient::onWsDisconnected() { emit wsDisconnected(); }

void AdminClient::onWsTextMessage(const QString &message) {
    QJsonParseError pe;
    auto doc = QJsonDocument::fromJson(message.toUtf8(), &pe);
    if (pe.error == QJsonParseError::NoError && doc.isObject()) {
        emit wsEvent(doc.object());
    }
}

void AdminClient::anthropicMessage(const QJsonArray &messages, const QString &system,
                                   int maxTokens,
                                   std::function<void(const QJsonDocument &, const QString &)> cb) {
    // Prefer the saved OAuth bearer token; fall back to a raw API key
    // if the user pasted one but never signed in with claude.ai.
    QString bearer = OAuthHelper::accessToken();
    bool useOAuth  = OAuthHelper::hasFreshToken();
    if (!useOAuth && bearer.isEmpty() && m_anthropicKey.isEmpty()) {
        cb(QJsonDocument(), "Not signed in to Claude.ai and no API key configured "
                           "(use 'Sign in with Claude.ai' in Settings).");
        return;
    }

    auto fire = [this, messages, system, maxTokens, cb]() {
        QJsonObject body;
        body["model"]      = "claude-opus-4-7";
        body["max_tokens"] = maxTokens;
        body["messages"]   = messages;
        if (!system.isEmpty()) body["system"] = system;

        QNetworkRequest req((QUrl("https://api.anthropic.com/v1/messages")));
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        req.setRawHeader("anthropic-version", "2023-06-01");
        QString at = OAuthHelper::accessToken();
        if (!at.isEmpty()) {
            req.setRawHeader("Authorization", ("Bearer " + at).toUtf8());
            req.setRawHeader("anthropic-beta", "oauth-2025-04-20");
        } else {
            req.setRawHeader("x-api-key", m_anthropicKey.toUtf8());
        }
        QNetworkReply *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
        replyToCb(r, cb);
    };

    if (!useOAuth && !OAuthHelper::refreshTokenStored().isEmpty()) {
        // Have a refresh token but the access token is stale → refresh first.
        auto *o = new OAuthHelper(this);
        o->refresh([fire, o, cb](bool ok, const QString &err) {
            o->deleteLater();
            if (!ok) { cb(QJsonDocument(), "Auto-refresh failed: " + err); return; }
            fire();
        });
        return;
    }
    fire();
}
