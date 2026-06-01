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

    // Live admin login. Posts username + password to the appropriate
    // endpoint, stashes the returned session cookie, and reconnects the
    // /ws/admin WebSocket so live events start flowing. callback gets
    // (true, "") on success or (false, error_message).
    void adminLogin(const QString &username, const QString &password,
                    std::function<void(bool, const QString &)> cb);
    void adminLogout(std::function<void(bool)> cb);

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
#ifdef SHROUD_ADMIN_HAS_WS
    QWebSocket m_ws;
#endif
    bool m_acceptSelfSigned = true;

    QNetworkRequest buildReq(const QString &fullUrl, const QString &contentType = "");
    void applyProxy();
};

#endif
