#include "oauth_helper.h"
#include <QSettings>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QUrl>
#include <QUrlQuery>
#include <QtNetwork/QTcpSocket>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QDateTime>

// Anthropic OAuth endpoints. These are the same endpoints Claude Code
// uses; the client_id is the Claude Code public OAuth app identifier.
// This admin client is operator-only and never distributed publicly
// (see clients/windows-admin/README.md), so we ride the same OAuth
// surface a Pro/Max account would when signing into Claude Code.
static const char *AUTH_URL  = "https://claude.ai/oauth/authorize";
static const char *TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
static const char *CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
static const char *SCOPES    = "org:create_api_key user:profile user:inference";

QString OAuthHelper::b64url(const QByteArray &raw) {
    QString s = QString::fromLatin1(raw.toBase64(QByteArray::Base64UrlEncoding));
    // Strip padding for OAuth PKCE canonical form
    while (s.endsWith('=')) s.chop(1);
    return s;
}

QByteArray OAuthHelper::randomBytes(int n) {
    QByteArray out(n, 0);
    auto *gen = QRandomGenerator::system();
    for (int i = 0; i < n; ++i) out[i] = char(gen->bounded(256));
    return out;
}

OAuthHelper::OAuthHelper(QObject *parent) : QObject(parent) {}

QString OAuthHelper::accessToken() {
    return QSettings("SHROUD", "admin").value("anthropic_access_token").toString();
}
QString OAuthHelper::refreshTokenStored() {
    return QSettings("SHROUD", "admin").value("anthropic_refresh_token").toString();
}
qint64 OAuthHelper::expiresAt() {
    return QSettings("SHROUD", "admin").value("anthropic_expires_at", 0).toLongLong();
}
bool OAuthHelper::hasFreshToken() {
    QString t = accessToken();
    if (t.isEmpty()) return false;
    qint64 now = QDateTime::currentSecsSinceEpoch();
    // 30s slop so we don't race the server-side expiry check
    return expiresAt() > now + 30;
}
void OAuthHelper::clear() {
    QSettings s("SHROUD", "admin");
    s.remove("anthropic_access_token");
    s.remove("anthropic_refresh_token");
    s.remove("anthropic_expires_at");
    s.remove("anthropic_account_email");
}

void OAuthHelper::start(std::function<void(bool, const QString &)> cb) {
    m_cb = std::move(cb);

    // PKCE: high-entropy verifier + S256 challenge
    m_codeVerifier = b64url(randomBytes(32));
    QString challenge = b64url(QCryptographicHash::hash(
        m_codeVerifier.toUtf8(), QCryptographicHash::Sha256));
    m_state = b64url(randomBytes(16));

    // Bring up a loopback listener on a free port
    if (m_server) { m_server->deleteLater(); m_server = nullptr; }
    m_server = new QTcpServer(this);
    if (!m_server->listen(QHostAddress::LocalHost, 0)) {
        m_cb(false, "Could not open loopback listener: " + m_server->errorString());
        return;
    }
    m_port = m_server->serverPort();
    connect(m_server, &QTcpServer::newConnection,
            this, &OAuthHelper::onIncomingConnection);

    // Compose authorize URL + open browser
    QUrl u(AUTH_URL);
    QUrlQuery q;
    q.addQueryItem("client_id", CLIENT_ID);
    q.addQueryItem("response_type", "code");
    q.addQueryItem("redirect_uri", QString("http://localhost:%1/callback").arg(m_port));
    q.addQueryItem("scope", SCOPES);
    q.addQueryItem("code_challenge", challenge);
    q.addQueryItem("code_challenge_method", "S256");
    q.addQueryItem("state", m_state);
    u.setQuery(q);
    if (!QDesktopServices::openUrl(u)) {
        m_cb(false, "Could not open system browser.");
    }
}

void OAuthHelper::onIncomingConnection() {
    while (auto *sock = m_server->nextPendingConnection()) {
        connect(sock, &QTcpSocket::readyRead, this, &OAuthHelper::onCallbackRead);
        connect(sock, &QTcpSocket::disconnected, sock, &QObject::deleteLater);
    }
}

void OAuthHelper::onCallbackRead() {
    auto *sock = qobject_cast<QTcpSocket *>(sender());
    if (!sock) return;
    QByteArray req = sock->readAll();
    // Extract path from first request line — only GET /callback?... HTTP/1.1
    int p = req.indexOf(' ');
    int q = req.indexOf(' ', p + 1);
    if (p < 0 || q < 0) return;
    QString path = QString::fromUtf8(req.mid(p + 1, q - p - 1));
    QUrl u(QString("http://localhost") + path);
    QUrlQuery qry(u);
    QString code  = qry.queryItemValue("code");
    QString state = qry.queryItemValue("state");
    QString err   = qry.queryItemValue("error");

    // Send the browser a friendly page and close
    QByteArray html =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
        "<html><body style='font-family:sans-serif;background:#111;color:#eee;"
        "padding:40px;'><h2>SHROUD admin sign-in complete</h2>"
        "<p>You can close this tab and return to <code>shroud-admin</code>.</p>"
        "</body></html>";
    sock->write(html);
    sock->flush();
    sock->disconnectFromHost();

    m_server->close();

    if (!err.isEmpty()) {
        if (m_cb) m_cb(false, "OAuth error: " + err);
        return;
    }
    if (state != m_state) {
        if (m_cb) m_cb(false, "OAuth state mismatch — possible CSRF.");
        return;
    }
    if (code.isEmpty()) {
        if (m_cb) m_cb(false, "OAuth callback returned no code.");
        return;
    }
    exchangeCode(code);
}

void OAuthHelper::exchangeCode(const QString &code) {
    QNetworkRequest req((QUrl(TOKEN_URL)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject body;
    body["grant_type"]    = "authorization_code";
    body["client_id"]     = CLIENT_ID;
    body["code"]          = code;
    body["redirect_uri"]  = QString("http://localhost:%1/callback").arg(m_port);
    body["code_verifier"] = m_codeVerifier;

    auto *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(r, &QNetworkReply::finished, [this, r]() {
        QByteArray resp = r->readAll();
        int http = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        r->deleteLater();
        if (http != 200) {
            if (m_cb) m_cb(false, QString("Token exchange failed (%1): %2")
                .arg(http).arg(QString::fromUtf8(resp.left(200))));
            return;
        }
        persist(resp);
        if (m_cb) m_cb(true, "");
    });
}

void OAuthHelper::refresh(std::function<void(bool, const QString &)> cb) {
    m_cb = std::move(cb);
    QString rt = refreshTokenStored();
    if (rt.isEmpty()) { m_cb(false, "No refresh token saved."); return; }

    QNetworkRequest req((QUrl(TOKEN_URL)));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QJsonObject body;
    body["grant_type"]    = "refresh_token";
    body["client_id"]     = CLIENT_ID;
    body["refresh_token"] = rt;

    auto *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(r, &QNetworkReply::finished, [this, r]() {
        QByteArray resp = r->readAll();
        int http = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        r->deleteLater();
        if (http != 200) {
            if (m_cb) m_cb(false, QString("Refresh failed (%1): %2")
                .arg(http).arg(QString::fromUtf8(resp.left(200))));
            return;
        }
        persist(resp);
        if (m_cb) m_cb(true, "");
    });
}

void OAuthHelper::persist(const QByteArray &tokenJson) {
    QJsonObject o = QJsonDocument::fromJson(tokenJson).object();
    QString at = o.value("access_token").toString();
    QString rt = o.value("refresh_token").toString();
    qint64 lifetime = o.value("expires_in").toVariant().toLongLong();
    if (lifetime <= 0) lifetime = 3600;  // sane default if Anthropic omits it
    QSettings s("SHROUD", "admin");
    if (!at.isEmpty()) s.setValue("anthropic_access_token",  at);
    if (!rt.isEmpty()) s.setValue("anthropic_refresh_token", rt);
    s.setValue("anthropic_expires_at",
               QDateTime::currentSecsSinceEpoch() + lifetime);
    // Capture identity if returned in the same response (optional)
    QString email = o.value("account").toObject().value("email").toString();
    if (!email.isEmpty()) s.setValue("anthropic_account_email", email);
}
