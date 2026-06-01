// admin_client.h — central REST + WebSocket client used by every tab.
//
// PRIVATE — see ../README.md.
#ifndef SHROUD_ADMIN_CLIENT_H
#define SHROUD_ADMIN_CLIENT_H

#include <QObject>
#include <QString>
#include <QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QSettings>
#include <functional>

#ifdef SHROUD_ADMIN_HAS_WS
#include <QtWebSockets/QWebSocket>
#endif

class AdminClient : public QObject {
    Q_OBJECT
public:
    explicit AdminClient(QObject *parent = nullptr);

    void   setRelayUrl(const QString &url);
    QString relayUrl() const { return m_relayUrl; }

    void   setAdminSessionCookie(const QString &cookie);
    QString adminSessionCookie() const { return m_sessionCookie; }

    void   setAnthropicKey(const QString &k);
    QString anthropicKey() const { return m_anthropicKey; }

    // Route via a SOCKS5 proxy (e.g. "127.0.0.1:9050" for local Tor).
    // Empty string disables proxying.
    void   setSocksProxy(const QString &hostPort);
    QString socksProxy() const { return m_socksProxy; }

    // Admin auth. The relay's admin auth model is a 256-char hex
    // fingerprint (minted at first-time setup) plus an optional
    // password. POSTs to /api/v1/admin/fingerprint-login, captures
    // the shroud_sid + shroud_csrf cookies. Callback fires with
    // (true,"") on success or (false, error).
    void adminLogin(const QString &fingerprintId, const QString &password,
                    std::function<void(bool, const QString &)> cb);

    // First-time setup. Only succeeds when the admin table is empty.
    // Server mints a fresh fingerprint and returns it; callback fires
    // with (fingerprint_hex, error).
    void adminFirstTimeSetup(
        std::function<void(const QString &fp, const QString &err)> cb);

    void adminLogout(std::function<void(bool)> cb);

    // Convenience — current X-CSRF-Token value, derived from the
    // shroud_csrf cookie captured at login. POST/DELETE callers add
    // this as a header.
    QString csrfToken() const { return m_csrfToken; }
    void    setCsrfToken(const QString &t);

    // Persistent fingerprint storage so the operator doesn't have to
    // paste the 256-char hex every launch.
    QString savedFingerprint() const;
    void    setSavedFingerprint(const QString &fp);

    // GET wrappers. Callback receives (parsed json, error string).
    void getJson(const QString &path,
                 std::function<void(const QJsonDocument &, const QString &)> cb);
    void postJson(const QString &path, const QJsonObject &body,
                  std::function<void(const QJsonDocument &, const QString &)> cb);
    void deleteRequest(const QString &path,
                       std::function<void(const QJsonDocument &, const QString &)> cb);

    // WebSocket for live admin events (/ws/admin)
    void connectAdminWs();
    void disconnectAdminWs();

    // Anthropic API — POST /v1/messages
    void anthropicMessage(const QJsonArray &messages,
                          const QString &system,
                          int maxTokens,
                          std::function<void(const QJsonDocument &, const QString &)> cb);

signals:
    void wsConnected();
    void wsDisconnected();
    void wsEvent(const QJsonObject &event);

private slots:
    void onWsConnected();
    void onWsDisconnected();
    void onWsTextMessage(const QString &message);

private:
    QNetworkAccessManager m_nam;
    QString m_relayUrl;
    QString m_sessionCookie;
    QString m_anthropicKey;
    QString m_socksProxy;
    QString m_csrfToken;
#ifdef SHROUD_ADMIN_HAS_WS
    QWebSocket m_ws;
#endif
    bool m_acceptSelfSigned = true;

    QNetworkRequest buildReq(const QString &fullUrl, const QString &contentType = "");
    void applyProxy();
};

#endif
