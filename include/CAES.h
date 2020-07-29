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
    // AES密钥(需要用根据密钥类型,申请空间,即quint8[emKeyType]大小;
    // 不能用QString转QByteArray转char*的方式,因为无法在后面补上'/0')
    explicit CAES(quint8 *pucKey, AESKeyType emKeyType = EM_AES_128);
    ~CAES();

    /*!
     * \brief AESEncryptionFile AES加密文件
     * \param pOriginFile       [in]        源文件QFile指针
     * \param pEncryptFile      [in]        加密后文件QFile指针
     * \return 成功/失败
     */
    bool AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile);
    /*!
     * \brief AESEncryptionFile AES加密文件
     * \param sOriginFileName   [in]        源文件的文件名
     * \param sEncryptFileName  [in]        加密后文件的文件名
     * \return 成功/失败
     */
    bool AESEncryptionFile(QString sOriginFileName, QString sEncryptFileName);
    /*!
     * \brief AESDecryptionFile AES解密文件
     * \param pOriginFile       [in]        源文件QFile指针
     * \param pDecryptFile      [in]        解密后文件QFile指针
     * \return 成功/失败
     */
    bool AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile);
    /*!
     * \brief AESDecryptionFile AES解密文件
     * \param sOriginFileName   [in]        源文件的文件名
     * \param sDecryptFileName  [in]        加密后文件的文件名
     * \return
     */
    bool AESDecryptionFile(QString sOriginFileName, QString sDecryptFileName);

    /*!
     * \brief AESEncryptionString AES加密
     * \param pOriginData         [in]      源数据指针
     * \param ulDataInLength      [in]      输入数据长度
     * \param pEncryptData        [in&out]  加密后数据指针
     * \return 加密后数据长度 大于0则成功 等于-1则失败
     */
    quint32 AESEncryption(const void *pOriginData, quint32 ulDataInLength, void *pEncryptData);
    /*!
     * \brief AESDecryptionString AES解密
     * \param pOriginData         [in]      源数据指针
     * \param ulDataInLength      [in]      输入数据长度
     * \param pDecryptData        [in&out]  解密后数据指针
     * \return 解密后数据长度 大于0则成功 等于-1则失败
     */
    quint32 AESDecryption(const void *pOriginData, quint32 ulDataInLength, void *pDecryptData);

    ///(由于加密过程可能出现'/0',所以用QByteArray, 而不用QString)
    /*!
     * \brief AESEncryptionString AES加密字节数组
     * \param baOriginData         [in]      源字节数组
     * \param baEncryptData        [in&out]  加密后字节数组
     * \return 成功/失败
     */
    bool AESEncryptionByteArray(const QByteArray baOriginData, QByteArray &baEncryptData);
    /*!
     * \brief AESDecryptionString AES加密字节数组
     * \param baOriginData         [in]      源字节数组
     * \param baDecryptData        [in&out]  解密后字节数组
     * \return 成功/失败
     */
    bool AESDecryptionByteArray(const QByteArray baOriginData, QByteArray &baDecryptData);

    /*!
     * \brief setKey        设置密钥
     * \param pucKey        [in]        AES密钥(需要用根据密钥类型,申请空间,即quint8[emKeyType]大小;
     *                                         不能用QString转QByteArray转char*的方式,因为无法在后面补上'/0')
     * \param emKeyType     [in]        AES密钥类型
     * \return
     */
    bool setKey(quint8 *pucKey, AESKeyType emKeyType = EM_AES_128);

private:
    QScopedPointer<CAESPrivate>     d_ptr;
};

#endif // CAES_H
