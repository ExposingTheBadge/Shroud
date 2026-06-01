#include "admin_client.h"
#include <QSslConfiguration>
#include <QtNetwork/QNetworkCookie>
#include <QtNetwork/QNetworkProxy>
#include <QUrlQuery>

AdminClient::AdminClient(QObject *parent) : QObject(parent) {
    QSettings s("SHROUD", "admin");
    m_relayUrl       = s.value("relay_url", "https://44.202.225.57:58443").toString();
    m_anthropicKey   = s.value("anthropic_key", "").toString();
    m_sessionCookie  = s.value("admin_session", "").toString();
    m_socksProxy     = s.value("socks_proxy", "").toString();
    applyProxy();

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

void AdminClient::adminLogin(const QString &username, const QString &password,
                             std::function<void(bool, const QString &)> cb) {
    QJsonObject body;
    body["username"] = username;
    body["password"] = password;
    QNetworkRequest req = buildReq(m_relayUrl + "/api/v1/admin/login", "application/json");
    QNetworkReply *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    QObject::connect(r, &QNetworkReply::finished, [this, r, cb]() {
        if (r->error() != QNetworkReply::NoError) {
            QString detail = QString::fromUtf8(r->readAll());
            r->deleteLater();
            cb(false, detail.isEmpty() ? r->errorString() : detail);
            return;
        }
        // Capture the session cookie set by the server
        auto cookies = qvariant_cast<QList<QNetworkCookie>>(
            r->header(QNetworkRequest::SetCookieHeader));
        for (const auto &c : cookies) {
            if (c.name() == "shroud_admin") {
                setAdminSessionCookie(QString::fromUtf8(c.value()));
                break;
            }
        }
        r->deleteLater();
        connectAdminWs();
        cb(true, "");
    });
}

void AdminClient::adminLogout(std::function<void(bool)> cb) {
    postJson("/api/v1/admin/logout", QJsonObject(),
             [this, cb](const QJsonDocument &, const QString &err) {
        setAdminSessionCookie("");
        disconnectAdminWs();
        cb(err.isEmpty());
    });
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
        req.setRawHeader("Cookie", QString("shroud_admin=%1").arg(m_sessionCookie).toUtf8());
        req.setRawHeader("X-CSRF-Token", m_sessionCookie.toUtf8());
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
        req.setRawHeader("Cookie", QString("shroud_admin=%1").arg(m_sessionCookie).toUtf8());
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
    if (m_anthropicKey.isEmpty()) {
        cb(QJsonDocument(), "Anthropic API key not configured (set in Settings tab)");
        return;
    }
    QJsonObject body;
    body["model"]      = "claude-opus-4-7";
    body["max_tokens"] = maxTokens;
    body["messages"]   = messages;
    if (!system.isEmpty()) body["system"] = system;

    QNetworkRequest req((QUrl("https://api.anthropic.com/v1/messages")));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("x-api-key", m_anthropicKey.toUtf8());
    req.setRawHeader("anthropic-version", "2023-06-01");
    QNetworkReply *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    replyToCb(r, cb);
}
