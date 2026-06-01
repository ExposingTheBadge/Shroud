#include "oauth_helper.h"
#include <QSettings>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QUrl>
#include <QUrlQuery>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRandomGenerator>
#include <QDateTime>

// Anthropic OAuth endpoints. These match what Claude Code uses; the
// client_id is the Claude Code public OAuth app identifier. The
// shroud-admin EXE is operator-only (clients/windows-admin/README.md
// states it's never shipped publicly), and OAuth scopes match what a
// Pro/Max account would grant Claude Code itself.
//
// Anthropic does NOT honor loopback redirect URIs for this OAuth app;
// the only allowed redirect is console.anthropic.com/oauth/code/callback,
// which renders the auth code in the URL fragment+query for the user
// to copy. We follow the same pattern as Claude Code's terminal flow:
// open the browser, then prompt the operator to paste the code back.
static const char *AUTH_URL  = "https://claude.ai/oauth/authorize";
static const char *TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
static const char *CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
static const char *SCOPES    = "org:create_api_key user:profile user:inference";

QString OAuthHelper::redirectUri() {
    return "https://console.anthropic.com/oauth/code/callback";
}

QString OAuthHelper::b64url(const QByteArray &raw) {
    QString s = QString::fromLatin1(raw.toBase64(QByteArray::Base64UrlEncoding));
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
    return expiresAt() > now + 30;
}
void OAuthHelper::clear() {
    QSettings s("SHROUD", "admin");
    s.remove("anthropic_access_token");
    s.remove("anthropic_refresh_token");
    s.remove("anthropic_expires_at");
    s.remove("anthropic_account_email");
}

QString OAuthHelper::authorizeUrl() const {
    QString challenge = b64url(QCryptographicHash::hash(
        m_codeVerifier.toUtf8(), QCryptographicHash::Sha256));

    // QUrlQuery::addQueryItem only encodes characters Qt considers
    // unsafe in a generic query string — it leaves ':' and '/' alone.
    // Anthropic's OAuth validator requires strict percent-encoding of
    // redirect_uri and scope (matching what Claude Code emits via
    // encodeURIComponent), otherwise rejects with 'Invalid request
    // format' before even reaching the consent screen. Build the URL
    // by hand so we control encoding per parameter.
    auto enc = [](const QString &s) -> QString {
        return QString::fromUtf8(QUrl::toPercentEncoding(s));
    };
    return QString("%1?code=true"
                   "&client_id=%2"
                   "&response_type=code"
                   "&redirect_uri=%3"
                   "&scope=%4"
                   "&code_challenge=%5"
                   "&code_challenge_method=S256"
                   "&state=%6")
        .arg(AUTH_URL)
        .arg(QString::fromUtf8(CLIENT_ID))
        .arg(enc(redirectUri()))
        .arg(enc(QString::fromUtf8(SCOPES)))
        .arg(challenge)       // base64url is already URL-safe
        .arg(m_state);        // base64url is already URL-safe
}

void OAuthHelper::start(std::function<void(bool, const QString &)> cb) {
    m_cb = std::move(cb);

    // Fresh PKCE pair + state for every attempt.
    m_codeVerifier = b64url(randomBytes(32));
    m_state        = b64url(randomBytes(16));

    if (!QDesktopServices::openUrl(QUrl(authorizeUrl()))) {
        if (m_cb) m_cb(false, "Could not open the system browser.");
    }
    // The UI is responsible for collecting the code from the user and
    // calling finishWithCode().
}

void OAuthHelper::finishWithCode(const QString &codeBlob) {
    // Anthropic's callback page renders the code as
    //   <code>#<state>
    // (or sometimes just <code>). Accept either form, and tolerate the
    // user pasting the entire query string.
    QString code = codeBlob.trimmed();

    // Pull out any leading auth-code from a full URL the user pasted.
    if (code.contains("?")) {
        QUrl u(code);
        QUrlQuery q(u);
        QString c = q.queryItemValue("code");
        if (!c.isEmpty()) code = c;
    }
    // Strip a trailing #state if present.
    int hash = code.indexOf('#');
    if (hash >= 0) code = code.left(hash);
    code = code.trimmed();

    if (code.isEmpty()) {
        if (m_cb) m_cb(false, "Empty code after parse.");
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
    body["state"]         = m_state;
    body["redirect_uri"]  = redirectUri();
    body["code_verifier"] = m_codeVerifier;

    auto *r = m_nam.post(req, QJsonDocument(body).toJson(QJsonDocument::Compact));
    connect(r, &QNetworkReply::finished, [this, r]() {
        QByteArray resp = r->readAll();
        int http = r->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        r->deleteLater();
        if (http != 200) {
            if (m_cb) m_cb(false, QString("Token exchange failed (%1): %2")
                .arg(http).arg(QString::fromUtf8(resp.left(300))));
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
                .arg(http).arg(QString::fromUtf8(resp.left(300))));
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
    if (lifetime <= 0) lifetime = 3600;
    QSettings s("SHROUD", "admin");
    if (!at.isEmpty()) s.setValue("anthropic_access_token",  at);
    if (!rt.isEmpty()) s.setValue("anthropic_refresh_token", rt);
    s.setValue("anthropic_expires_at",
               QDateTime::currentSecsSinceEpoch() + lifetime);
    QString email = o.value("account").toObject().value("email").toString();
    if (!email.isEmpty()) s.setValue("anthropic_account_email", email);
}
