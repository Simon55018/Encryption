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
    explicit CAES(quint8 *pucKey, AESKeyType emKeyType = EM_AES_128);
    ~CAES();

    bool AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile);
    bool AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile);

    bool AESEncryptionString(void *pOriginData, quint32 ulDataInLength, void *pEncryptData);
    bool AESDecryptionString(void *pOriginData, quint32 ulDataInLength, void *pDecryptData);

    bool AESEncryption(quint8 *pucOriginData, quint8 *pucEncryptData,
                       quint8 *pucKey = 0, AESKeyType emKeyType = EM_AES_128);
    bool AESDecryption(quint8 *pucOriginData, quint8 *pucDecryptData,
                       quint8 *pucKey = 0, AESKeyType emKeyType = EM_AES_128);

private:
    QScopedPointer<CAESPrivate>     d_ptr;
};

#endif // CAES_H
