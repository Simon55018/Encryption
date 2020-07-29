#ifndef CKEYGENERATORWIDGET_H
#define CKEYGENERATORWIDGET_H

#include <QWidget>

namespace Ui {
class CKeyGeneratorWidget;
}

class CKeyGeneratorWidget : public QWidget
{
    Q_OBJECT

public:
    explicit CKeyGeneratorWidget(QWidget *parent = 0);
    ~CKeyGeneratorWidget();

private slots:
    void stGenerateKey();

private:
    Ui::CKeyGeneratorWidget *ui;
};

#endif // CKEYGENERATORWIDGET_H
