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
     * \brief AESEncryptionString AES加密字符串
     * \param pOriginData         [in]      源字符串指针
     * \param ulDataInLength      [in]      输入数据长度
     * \param pEncryptData        [in&out]  加密后字符串指针
     * \return 加密后字符串长度 大于0则成功 等于-1则失败
     */
    quint32 AESEncryptionString(char *pOriginData, quint32 ulDataInLength, char *pEncryptData);
    /*!
     * \brief AESDecryptionString AES解密字符串
     * \param pOriginData         [in]      源字符串指针
     * \param ulDataInLength      [in]      输入数据长度
     * \param pDecryptData        [in&out]  解密后字符串指针
     * \return 解密后字符串长度 大于0则成功 等于-1则失败
     */
    quint32 AESDecryptionString(char *pOriginData, quint32 ulDataInLength, char *pDecryptData);

    /*!
     * \brief AESEncryptionString AES加密字符串
     * \param sOriginData         [in]      源字符串
     * \param sEncryptData        [in&out]  加密后字符串
     * \return 成功/失败
     */
    bool AESEncryptionString(const QString sOriginData, QString &sEncryptData);
    /*!
     * \brief AESDecryptionString AES加密字符串
     * \param sOriginData         [in]      源字符串
     * \param sDecryptData        [in&out]  解密后字符串
     * \return 成功/失败
     */
    bool AESDecryptionString(const QString sOriginData, QString &sDecryptData);

    /*!
     * \brief AESEncryption     AES加密(每次只能加密16bit)
     * \param pucOriginData     [in]        源字符串
     * \param pucEncryptData    [in&out]    加密后字符串
     * \param pucKey            [in]        密钥
     * \param emKeyType         [in]        AES密钥类型
     * \return 加密字符串长度, 等于-1则失败
     */
    quint32 AESEncryption(char *pucOriginData, char *pucEncryptData,
                          char *pucKey = 0, AESKeyType emKeyType = EM_AES_128);
    /*!
     * \brief AESDecryption     AES解密(每次只能解密16bit)
     * \param pucOriginData     [in]        源字符串
     * \param pucDecryptData    [in&out]    解密密后字符串
     * \param pucKey            [in]        AES密钥
     * \param emKeyType         [in]        AES密钥类型
     * \return 解密字符串长度, 等于-1则失败
     */
    quint32 AESDecryption(char *pucOriginData, char *pucDecryptData,
                          char *pucKey = 0, AESKeyType emKeyType = EM_AES_128);

    /*!
     * \brief setKey        设置密钥
     * \param pucKey        [in]        AES密钥
     * \param emKeyType     [in]        AES密钥类型
     * \return
     */
    bool setKey(char *pucKey, AESKeyType emKeyType = EM_AES_128);

private:
    QScopedPointer<CAESPrivate>     d_ptr;
};

#endif // CAES_H
