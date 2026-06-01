#ifndef SHROUD_ADMIN_CLAUDE_CHAT_TAB_H
#define SHROUD_ADMIN_CLAUDE_CHAT_TAB_H
#include <QWidget>
#include <QJsonArray>
class QTextBrowser; class QPlainTextEdit; class QPushButton; class QLabel;
class AdminClient;

class ClaudeChatTab : public QWidget {
    Q_OBJECT
public:
    explicit ClaudeChatTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onSend();
    void onClear();
    void onLoadFederationContext();
private:
    AdminClient *m_client;
    QTextBrowser *m_history;
    QPlainTextEdit *m_input;
    QPushButton *m_sendBtn, *m_clearBtn, *m_loadCtxBtn;
    QLabel *m_status;
    QJsonArray m_messages;
    QString m_systemPrompt;
};
#endif
