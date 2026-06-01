#ifndef SHROUD_ADMIN_CONTROLS_TAB_H
#define SHROUD_ADMIN_CONTROLS_TAB_H
#include <QWidget>
class QPushButton; class QLabel;
class AdminClient;

class ControlsTab : public QWidget {
    Q_OBJECT
public:
    explicit ControlsTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void runAction(const QString &slug, const QString &confirmMsg);
    void refreshFlags();
private:
    AdminClient *m_client;
    QLabel *m_status;
    QPushButton *m_regBtn, *m_mntBtn, *m_onionBtn;
};
#endif
