#ifndef SHROUD_ADMIN_RELAY_SSH_TAB_H
#define SHROUD_ADMIN_RELAY_SSH_TAB_H
#include <QWidget>
class QPlainTextEdit; class QPushButton; class QComboBox; class QLineEdit;
class QProcess;
class AdminClient;

class RelaySshTab : public QWidget {
    Q_OBJECT
public:
    explicit RelaySshTab(AdminClient *client, QWidget *parent = nullptr);
private slots:
    void runOnAll(const QString &cmd, const QString &label);
    void runCustom();
    void onOutput();
private:
    AdminClient *m_client;
    QPlainTextEdit *m_output;
    QComboBox *m_targetBox;
    QLineEdit *m_customCmd;
    QPushButton *m_customRunBtn;
    QPushButton *m_pullBtn, *m_restartBtn, *m_torStatusBtn, *m_vacuumBtn, *m_journalBtn;
    QProcess *m_proc;
};
#endif
