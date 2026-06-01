#ifndef SHROUD_ADMIN_MANIFEST_TAB_H
#define SHROUD_ADMIN_MANIFEST_TAB_H
#include <QWidget>
class QLineEdit; class QPlainTextEdit; class QPushButton;
class QProcess;
class AdminClient;

class ManifestTab : public QWidget {
    Q_OBJECT
public:
    explicit ManifestTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void onBuild();
    void onView();
    void onProcessOutput();
    void onProcessFinished(int code);
private:
    AdminClient *m_client;
    QLineEdit *m_keyfile, *m_homeRelay, *m_diagPub, *m_outPath;
    QLineEdit *m_ttlDays, *m_stickerCdn;
    QPlainTextEdit *m_output;
    QPushButton *m_buildBtn, *m_viewBtn;
    QProcess *m_proc;
};
#endif
