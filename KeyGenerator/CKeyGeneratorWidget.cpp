#include "CKeyGeneratorWidget.h"
#include "ui_CKeyGeneratorWidget.h"

CKeyGeneratorWidget::CKeyGeneratorWidget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::CKeyGeneratorWidget)
{
    ui->setupUi(this);

    // 输入限制
    QRegExp regKeySource("[a-zA-Z0-9]{0,32}");
    ui->leditKeySource->setValidator(new QRegExpValidator(regKeySource));

    connect(ui->pbtnGenerate, SIGNAL(clicked(bool)), this, SLOT(stGenerateKey()));
}

CKeyGeneratorWidget::~CKeyGeneratorWidget()
{
    delete ui;
}

void CKeyGeneratorWidget::stGenerateKey()
{
    char *key = (char*)calloc(32, sizeof(char));
    QString sSourceKey = ui->leditKeySource->text();
    key = sSourceKey.toLatin1().data();
    memcpy(sSourceKey.toLatin1().data(), key, 32*sizeof(char));
    QByteArray baKeyHex = QByteArray::fromRawData(key, 32).toBase64();
    ui->leditKeyEncry->setText(QString(baKeyHex));
}
