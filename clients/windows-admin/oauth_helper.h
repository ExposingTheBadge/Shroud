// OAuth PKCE flow for claude.ai. Opens the system browser to the
// Anthropic authorize URL, listens on a loopback port for the
// redirect, exchanges the code for an access+refresh token pair, and
// persists them in QSettings so subsequent launches don't re-prompt.
//
// On every API call AdminClient first checks if a non-expired access
// token is on hand; if not but a refresh token is, it transparently
// refreshes; if neither, it falls back to the legacy x-api-key field.
#ifndef SHROUD_ADMIN_OAUTH_HELPER_H
#define SHROUD_ADMIN_OAUTH_HELPER_H

#include <QObject>
#include <QString>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QTcpServer>
#include <functional>

class OAuthHelper : public QObject {
    Q_OBJECT
public:
    explicit OAuthHelper(QObject *parent = nullptr);

    // Start the browser flow. Anthropic's OAuth only honors a fixed
    // redirect_uri (https://console.anthropic.com/oauth/code/callback),
    // so the user authorizes, copies the displayed code, and pastes
    // it back via finishWithCode(). The callback fires once both
    // halves complete.
    void start(std::function<void(bool, const QString &)> cb);

    // Called by the UI after the user pastes the code from the
    // Anthropic callback page.
    void finishWithCode(const QString &codeBlob);

    // Just the authorize URL for the current PKCE state. Useful when
    // the caller wants to render the URL in the UI instead of opening
    // the browser directly.
    QString authorizeUrl() const;

    // Refresh the access token using the saved refresh_token. Useful
    // when the access token is expired. Callback fires once.
    void refresh(std::function<void(bool, const QString &)> cb);

    // Convenience accessors over QSettings keys.
    static QString accessToken();
    static QString refreshTokenStored();
    static qint64  expiresAt();
    static bool    hasFreshToken();
    static void    clear();

private:
    QNetworkAccessManager m_nam;
    QString               m_codeVerifier;
    QString               m_state;
    std::function<void(bool, const QString &)> m_cb;

    static QString b64url(const QByteArray &raw);
    static QByteArray randomBytes(int n);
    static QString redirectUri();
    void exchangeCode(const QString &code);
    void persist(const QByteArray &tokenJson);
};

#endif
