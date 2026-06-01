#ifndef SHROUD_ADMIN_LOGS_TAB_H
#define SHROUD_ADMIN_LOGS_TAB_H
#include <QWidget>
class QPlainTextEdit; class QLineEdit; class QComboBox; class QPushButton;
class AdminClient;
class QJsonObject;

class LogsTab : public QWidget {
    Q_OBJECT
public:
    explicit LogsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onEvent(const QJsonObject &event);
    void onConnect();
    void onClear();
private:
    AdminClient *m_client;
    QPlainTextEdit *m_view;
    QComboBox *m_filter;
    QLineEdit *m_search;
    QPushButton *m_connectBtn;
    QPushButton *m_clearBtn;
    bool m_connected = false;
};
#endif
