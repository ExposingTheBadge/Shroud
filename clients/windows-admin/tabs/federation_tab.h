#ifndef SHROUD_ADMIN_FEDERATION_TAB_H
#define SHROUD_ADMIN_FEDERATION_TAB_H
#include <QWidget>
#include <QTimer>
class QGridLayout; class QVBoxLayout; class QLabel; class QPushButton;
class AdminClient;

class FederationTab : public QWidget {
    Q_OBJECT
public:
    explicit FederationTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void refresh();
private:
    AdminClient *m_client;
    QGridLayout *m_grid;          // relay cards
    QLabel      *m_summary;
    QPushButton *m_refreshBtn;
    QTimer       m_timer;
};
#endif
