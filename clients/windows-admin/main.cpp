// main.cpp — entry point. PRIVATE — see README.md.
#include <QApplication>
#include "admin_window.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("SHROUD Admin");
    app.setOrganizationName("SHROUD");
    app.setApplicationVersion(SHROUD_ADMIN_VERSION);

    AdminWindow w;
    w.show();
    return app.exec();
}
