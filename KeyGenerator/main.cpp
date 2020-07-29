#include "CKeyGeneratorWidget.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    CKeyGeneratorWidget w;
    w.show();

    return a.exec();
}
