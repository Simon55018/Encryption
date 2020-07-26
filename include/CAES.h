#ifndef CAES_H
#define CAES_H

#include <QFile>
#include <QObject>
#include <QScopedPointer>

enum AESKeyType
{
    EM_AES_128 = 16,     // 密钥长度为128位
    EM_AES_192 = 24,     // 密钥长度为192位
    EM_AES_256 = 32,     // 密钥长度为256位
};

class CAESPrivate;
class CAES
{
    Q_DECLARE_PRIVATE(CAES)
    Q_DISABLE_COPY(CAES)

public:
    CAES();
    explicit CAES(char *pucKey, AESKeyType emKeyType = EM_AES_128);
    ~CAES();

    void AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile);
    void AESEncryptionFile(QString sOriginFileName, QString sEncryptFileName);
    void AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile);
    void AESDecryptionFile(QString sOriginFileName, QString sDecryptFileName);

    quint32 AESEncryptionString(void *pOriginData, quint32 ulDataInLength, void *pEncryptData);
    quint32 AESDecryptionString(void *pOriginData, quint32 ulDataInLength, void *pDecryptData);

    void AESEncryptionString(const QString sOriginData, QString &sEncryptData);
    void AESDecryptionString(const QString sOriginData, QString &sDecryptData);

    void AESEncryption(char *pucOriginData, char *pucEncryptData,
                       char *pucKey = 0, AESKeyType emKeyType = EM_AES_128);
    void AESDecryption(char *pucOriginData, char *pucDecryptData,
                       char *pucKey = 0, AESKeyType emKeyType = EM_AES_128);

    void setKey(char *pucKey, AESKeyType emKeyType = EM_AES_128);

private:
    QScopedPointer<CAESPrivate>     d_ptr;
};

#endif // CAES_H
