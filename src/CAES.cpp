#include "CAES_p.h"
#include <QDebug>

#define MAX_KEY_SIZE            32
#define SIZE_KEY_SCHEDULE       16*15

#define ROW_STATE_MATRIX        4
#define COLUMN_STATE_MATRIX     4
#define SIZE_STATE_MATRIX       ROW_STATE_MATRIX*COLUMN_STATE_MATRIX

#define NUMBER_ENCRYPTION       16
#define NUMBER_DECRYPTION       16

// 申请char*指针需考虑/0等问题,所以比加解密操作数多1位
#define SIZE_ENCRYPT_MALLOC     NUMBER_ENCRYPTION + 1
#define SIZE_DECRYPT_MALLOC     NUMBER_DECRYPTION + 1

CAES::CAES()
    : d_ptr(new CAESPrivate)
{
    d_ptr->q_ptr = NULL;
}

CAES::CAES(char *pucKey, AESKeyType emKeyType)
    : d_ptr(new CAESPrivate)
{
    d_ptr->q_ptr = NULL;

    setKey(pucKey, emKeyType);
}

CAES::~CAES()
{
}

bool CAES::AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return false;
    }

    // 申请内存
    char *aucInput = (char*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(char));
    char *aucOutput = (char*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(char));

    // 源文件只读打开,加密文件只写打开并重头开始写入
    if( pOriginFile->open(QIODevice::ReadOnly)
            && pEncryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // 循环读取源文件,直到文件末尾
        while(!pOriginFile->atEnd())
        {
            // 每次读取16位, 因为加密操作每次只能操作16位
            pOriginFile->read(aucInput, NUMBER_ENCRYPTION);
            AESEncryption(aucInput, aucOutput);
            // 将加密字符串写入
            pEncryptFile->write(aucOutput);

            // 重置内存
            memset(aucInput, 0, SIZE_ENCRYPT_MALLOC*sizeof(char));
            memset(aucOutput, 0, SIZE_ENCRYPT_MALLOC*sizeof(char));
        }
    }

    // 关闭文件
    pOriginFile->close();
    pEncryptFile->close();

    // 释放内存
    free(aucInput);
    aucInput = NULL;

    free(aucOutput);
    aucOutput = NULL;

    return true;
}

bool CAES::AESEncryptionFile(QString sOriginFileName, QString sEncryptFileName)
{
    // 创建QFile对象
    QFile fileOrigin(sOriginFileName);
    QFile fileEncrypt(sEncryptFileName);

    // 调用QFile对象对应解密函数
    return this->AESEncryptionFile(&fileOrigin, &fileEncrypt);
}

bool CAES::AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return false;
    }

    // 申请内存
    char *aucInput = (char*)calloc(SIZE_DECRYPT_MALLOC, sizeof(char));
    char *aucOutput = (char*)calloc(SIZE_DECRYPT_MALLOC, sizeof(char));

    // 源文件只读打开,解密文件只写打开并重头开始写入
    if( pOriginFile->open(QIODevice::ReadOnly)
            && pDecryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // 循环读取源文件,直到文件末尾
        while(!pOriginFile->atEnd())
        {
            // 每次读取16位, 因为解密操作每次只能操作16位
            pOriginFile->read(aucInput, NUMBER_DECRYPTION);
            AESDecryption(aucInput, aucOutput);
            // 将解密字符串写入
            pDecryptFile->write(aucOutput);

            // 重置内存
            memset(aucInput, 0, SIZE_DECRYPT_MALLOC*sizeof(char));
            memset(aucOutput, 0, SIZE_DECRYPT_MALLOC*sizeof(char));
        }
    }

    // 关闭文件
    pOriginFile->close();
    pDecryptFile->close();

    // 释放内存
    free(aucInput);
    aucInput = NULL;

    free(aucOutput);
    aucOutput = NULL;

    return true;
}

bool CAES::AESDecryptionFile(QString sOriginFileName, QString sDecryptFileName)
{
    // 创建QFile对象
    QFile fileOrigin(sOriginFileName);
    QFile fileDecrypt(sDecryptFileName);

    // 调用QFile对象对应解密函数
    return this->AESDecryptionFile(&fileOrigin, &fileDecrypt);
}

quint32 CAES::AESEncryptionString(char *pOriginData, quint32 ulDataInLength, char *pEncryptData)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return -1;
    }

    quint32 ulDataOutLength = 0;
    char *pucCurInBuff = pOriginData;
    char *pucCurOutBuff = pEncryptData;
    // 每块空间为16位,每次只操作一块空间
    quint32 ulBlockNUm = ulDataInLength / NUMBER_ENCRYPTION;
    // 超出16的倍数的字符串个数
    quint32 ulLeftNum = ulDataInLength % NUMBER_ENCRYPTION;

    // 按块操作
    for( quint32 i = 0; i < ulBlockNUm; ++i )
    {
        AESEncryption(pucCurInBuff, pucCurOutBuff);
        // 每次移位16个字符
        pucCurInBuff += NUMBER_ENCRYPTION;
        pucCurOutBuff += NUMBER_ENCRYPTION;
        // 记录操作字符长度
        ulDataOutLength += NUMBER_ENCRYPTION;
    }

    // 若字符串个数超过16的倍数
    if( ulLeftNum )
    {
        // 申请空间,补全16位数(其实就在后面补0)
        char *ucInBuffer = (char*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(char));
        // 赋最后ulLeftNum个char值
        memcpy(ucInBuffer, pucCurInBuff, ulLeftNum);
        AESEncryption(ucInBuffer, pucCurOutBuff);
        // 移位16个字符
        pucCurOutBuff += NUMBER_ENCRYPTION;
        // 记录操作字符长度
        ulDataOutLength += NUMBER_ENCRYPTION;

        // 释放内存
        free(ucInBuffer);
        ucInBuffer = NULL;
    }

    // 申请额外字符空间
    char *ucExtraBuff = (char*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(char));
    // 计算出额外字符个数,作为加密数据
    *((quint32*)ucExtraBuff) = NUMBER_ENCRYPTION +
                                (NUMBER_ENCRYPTION - ulLeftNum)%NUMBER_ENCRYPTION;
    // 加密操作
    AESEncryption(ucExtraBuff, pucCurOutBuff);
    // 记录操作字符长度
    ulDataOutLength += NUMBER_ENCRYPTION;

    // 释放内存
    free(ucExtraBuff);
    ucExtraBuff = NULL;

    return ulDataOutLength;
}

quint32 CAES::AESDecryptionString(char *pOriginData, quint32 ulDataInLength, char *pDecryptData)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return -1;
    }

    quint32 ulDataOutLength= 0;
    char *pucCurInBuff = pOriginData;
    char *pucCurOutBuff = pDecryptData;
    // 每块空间为16位,每次只操作一块空间
    quint32 ulBlockNum = ulDataInLength / NUMBER_DECRYPTION;
    // 超出16的倍数的字符串个数
    quint32 ulLeftNum = ulDataInLength % NUMBER_DECRYPTION;

    // 理论上加密后数据已经是16的倍数, 如果不是16的倍数,则说明数据有问题,返回错误
    if(ulLeftNum)
    {
        return -1;
    }

    // 按块操作
    for( quint32 i = 0; i < ulBlockNum; ++i)
    {
        AESDecryption(pucCurInBuff,pucCurOutBuff);
        // 每次移位16个字符
        pucCurInBuff += NUMBER_DECRYPTION;
        pucCurOutBuff += NUMBER_DECRYPTION;
        // 记录操作字符长度
        ulDataOutLength += NUMBER_DECRYPTION;
    }

    // 解密字符串最后16位为额外字符串
    char *pucExtraInBuff = pucCurOutBuff - NUMBER_DECRYPTION;
    // 算出额外字符串的长度
    quint32 ulExtraBytes=*((quint32 *)pucExtraInBuff);

    // 返回正确数据长度
    return (ulDataOutLength-ulExtraBytes);
}

bool CAES::AESEncryptionString(const QString sOriginData, QString &sEncryptData)
{
    bool bRet = false;

    // 加密数据长度
    quint32 ulDataInLength = (quint32)sOriginData.length();
    // 申请加密字符串内存,由于加密每次需要操作16个数据,若加密数据不为16的倍数,则补全到16个数据
    // 由于加密过程存在额外数据部分,额外数据为16个,所以多申请个16+16个char的内存
    char *pOutput = (char*)calloc(ulDataInLength + 32, sizeof(char));

    // 加密并获取加密后数据长度
    quint32 ulDataOutLength = this->AESEncryptionString(sOriginData.toLatin1().data(), ulDataInLength, pOutput);
    // 大于0则加密成功
    if( ulDataOutLength > 0 )
    {
        // 字符串转化为QString
        sEncryptData = QString::fromLatin1(pOutput, ulDataOutLength);
        bRet = true;
    }

    // 释放内存
    free(pOutput);
    pOutput = NULL;

    return bRet;
}

bool CAES::AESDecryptionString(const QString sOriginData, QString &sDecryptData)
{
    bool bRet = false;

    // 解密数据长度
    quint32 ulDataInLength = (quint32)sOriginData.length();
    // 申请解密字符串内存, 由于加密数据存在16个数据额外数据,所以可以少申请15个数据(留一位给'/0')
    char *pOutput = (char*)calloc(ulDataInLength - 16 + 1, sizeof(char));

    // 解密并获取解密后数据长度
    quint32 ulDataOutLength = this->AESDecryptionString(sOriginData.toLatin1().data(), ulDataInLength, pOutput);
    // 大于0则解密成功
    if( ulDataOutLength > 0 )
    {
        // 字符串转化为QString
        sDecryptData = QString::fromLatin1(pOutput, ulDataOutLength);
        bRet = true;
    }

    // 释放内存
    free(pOutput);
    pOutput = NULL;

    return bRet;
}

quint32 CAES::AESEncryption(char *pucOriginData, char *pucEncryptData, char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return -1;
    }

    // 如果pucKey不为空,则设置密钥信息
    if( pucKey )
    {
        setKey(pucKey, emKeyType);
    }
    // 重置状态矩阵数据
    memset(d->m_pucStateMatrix, 0, SIZE_STATE_MATRIX*sizeof(quint8));

    // 对状态矩阵赋原始值
    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + i/4] = (quint8)pucOriginData[i];
    }

    // 密钥轮加函数0轮
    d->keyAddRound(0);

    for( int round = 1; round <= (d->m_lRoundNumber - 1); ++round )
    {
        // 字节代换
        d->byteSubstitute();
        // 行移位
        d->rowShift();
        // 列混淆
        d->columnMix();
        // 密钥轮加
        d->keyAddRound(round);
    }
    // 字节代换
    d->byteSubstitute();
    // 行移位
    d->rowShift();
    // 密钥轮加
    d->keyAddRound(d->m_lRoundNumber);

    // 获取加密后信息
    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        pucEncryptData[i] = (char)d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + (i/4)];
    }

    // 返回加密信息长度
    return strlen(pucEncryptData);
}

quint32 CAES::AESDecryption(char *pucOriginData, char *pucDecryptData, char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType) )
    {
        return -1;
    }

    // 如果pucKey不为空,则设置密钥信息
    if( pucKey )
    {
        setKey(pucKey, emKeyType);
    }
    // 重置状态矩阵数据
    memset(d->m_pucStateMatrix, 0, SIZE_STATE_MATRIX*sizeof(quint8));

    // 对状态矩阵赋原始值
    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + i/4] = (quint8)pucOriginData[i];
    }

    // 密钥轮加
    d->keyAddRound(d->m_lRoundNumber);

    for( int round = d->m_lRoundNumber - 1; round >= 1; --round )
    {
        // 行移位逆变换
        d->rowInvertShift();
        // 字节代换逆变换
        d->byteInvertSubstitube();
        // 密钥轮加
        d->keyAddRound(round);
        // 列混淆逆变换
        d->columnInvertMix();
    }
    // 行移位逆变换
    d->rowInvertShift();
    // 字节代换逆变换
    d->byteInvertSubstitube();
    // 密钥轮加
    d->keyAddRound(0);

    // 获取解密后信息
    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        pucDecryptData[i] = (char)d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + (i/4)];
    }

    // 返回解密信息长度
    return strlen(pucDecryptData);
}

bool CAES::setKey(char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    d->m_emKeyType = emKeyType;
    // 密钥初始化
    bool bRet = d->runKeyExpansion(emKeyType, (quint8*)pucKey);

    return bRet;
}

CAESPrivate::CAESPrivate()
{
    q_ptr = NULL;
    m_pucKey = (quint8*)calloc(MAX_KEY_SIZE, sizeof(quint8));
    m_pucKeySchedule = (quint8*)calloc(SIZE_KEY_SCHEDULE, sizeof(quint8));
    m_pucStateMatrix = (quint8*)calloc(SIZE_STATE_MATRIX, sizeof(quint8));
}

CAESPrivate::~CAESPrivate()
{
    if( NULL != m_pucKey )
    {
        free(m_pucKey);
        m_pucKey = NULL;
    }

    if( NULL != m_pucKeySchedule )
    {
        free(m_pucKeySchedule);
        m_pucKeySchedule = NULL;
    }

    if( NULL != m_pucStateMatrix )
    {
        free(m_pucStateMatrix);
        m_pucStateMatrix = NULL;
    }
}

bool CAESPrivate::checkAESType(AESKeyType emKeyType)
{
    bool bRet = false;
    switch (emKeyType)
    {
        case EM_AES_128:
            bRet = true;
            break;

        case EM_AES_192:
            bRet = true;
            break;

        case EM_AES_256:
            bRet = true;
            break;

        // 如果不是上述类型,则返回错误
        default:
            bRet = false;
            break;
    }

    return bRet;
}

bool CAESPrivate::runKeyExpansion(AESKeyType emKeyType, quint8 *pucKey)
{
    bool bRet = setKeyLength(emKeyType);
    if( !bRet )
    {
        return bRet;
    }

    memcpy(m_pucKey, pucKey, emKeyType);
    expandKey();

    return true;
}

bool CAESPrivate::setKeyLength(AESKeyType emKeyType)
{
    if( !checkAESType(emKeyType) )
    {
        return false;
    }

    m_lBlockSize = 4;       // block size always = 4 words = 16 bytes = 128 bits for AES_ENDECRYPT
    switch (emKeyType)
    {
        case EM_AES_128:
        {
            m_lKeySize = 4;   //Key size = 4 words = 16 bytes = 128 bits
            m_lRoundNumber = 10;  // rounds for algorithm = 10
        }
        break;

        case EM_AES_192:
        {
            m_lKeySize = 6;   // 6 words = 24 bytes = 192 bits
            m_lRoundNumber = 12;
        }
        break;

        case EM_AES_256:
        {
            m_lKeySize = 8;   // 8 words = 32 bytes = 256 bits
            m_lRoundNumber = 14;
        }
        break;

        default:
        break;
    }

    return true;
}

void CAESPrivate::expandKey()
{
    memset(m_pucKeySchedule, 0, SIZE_KEY_SCHEDULE*sizeof(quint8));
    for( int row = 0; row < m_lKeySize; ++row)  //lKeySize=4,6,8得到初始密码
    {
        m_pucKeySchedule[4*row+0] = m_pucKey[4*row+0];
        m_pucKeySchedule[4*row+1] = m_pucKey[4*row+1];
        m_pucKeySchedule[4*row+2] = m_pucKey[4*row+2];
        m_pucKeySchedule[4*row+3] = m_pucKey[4*row+3];
    }

    quint8 *pucTemp = (quint8*)malloc(COLUMN_STATE_MATRIX*sizeof(quint8));
    quint8 *pucResultSub = (quint8*)malloc(COLUMN_STATE_MATRIX*sizeof(quint8));
    quint8 *pucResultShift = (quint8*)malloc(COLUMN_STATE_MATRIX*sizeof(quint8));
    //产生密匙顺序表
    for( int row = m_lKeySize; row < m_lBlockSize * (m_lRoundNumber+1); ++row)
    {
        pucTemp[0] = m_pucKeySchedule[4*(row-1)+0];
        pucTemp[1] = m_pucKeySchedule[4*(row-1)+1];
        pucTemp[2] = m_pucKeySchedule[4*(row-1)+2];
        pucTemp[3] = m_pucKeySchedule[4*(row-1)+3];

        if( row % m_lKeySize )
        {
            //keyShift接受4字节数组并将它们向左旋转位移1位. 由于轮回次序表w[]有四列,所以RotWord会将一行w[]向左旋转位移
            keyShift(pucTemp, pucResultShift);
            //keySubstitute使用置换表Sbox,针对密匙次序表w[]的给定行执行逐字节替换
            keySubstitute(pucResultShift, pucResultSub);
            memcpy(pucTemp, pucResultSub, 4*sizeof(quint8));

            pucTemp[0] = (quint8)( (qint32)pucTemp[0] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+0] );
            pucTemp[1] = (quint8)( (qint32)pucTemp[1] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+1] );
            pucTemp[2] = (quint8)( (qint32)pucTemp[2] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+2] );
            pucTemp[3] = (quint8)( (qint32)pucTemp[3] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+3] );
        }
        else if( m_lKeySize > 6 && ( 4 == row % m_lKeySize ) )
        {
            keySubstitute(pucTemp, pucResultSub);
            memcpy(pucTemp, pucResultSub, 4*sizeof(quint8));
        }

        // m_pucKeySchedule[row] = m_pucKeySchedule[row-m_lKeySize] xor pucTemp
        m_pucKeySchedule[4*row+0] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+0] ^ (qint32)pucTemp[0] );
        m_pucKeySchedule[4*row+1] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+1] ^ (qint32)pucTemp[1] );
        m_pucKeySchedule[4*row+2] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+2] ^ (qint32)pucTemp[2] );
        m_pucKeySchedule[4*row+3] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+3] ^ (qint32)pucTemp[3] );
    }

    free(pucTemp);
    pucTemp = NULL;

    free(pucResultSub);
    pucResultSub = NULL;

    free(pucResultShift);
    pucResultShift = NULL;
}

void CAESPrivate::keySubstitute(quint8 *pucInput, quint8 *pucOutput)
{
    pucOutput[0] =  m_aucSBox[ 16*(pucInput[0] >> 4)+ (pucInput[0] & 0x0f) ];
    pucOutput[1] =  m_aucSBox[ 16*(pucInput[1] >> 4)+ (pucInput[1] & 0x0f) ];
    pucOutput[2] =  m_aucSBox[ 16*(pucInput[2] >> 4)+ (pucInput[2] & 0x0f) ];
    pucOutput[3] =  m_aucSBox[ 16*(pucInput[3] >> 4)+ (pucInput[3] & 0x0f) ];
}

void CAESPrivate::keyShift(quint8 *pucInput, quint8 *pucOutput)
{
    pucOutput[0] = pucInput[1];
    pucOutput[1] = pucInput[2];
    pucOutput[2] = pucInput[3];
    pucOutput[3] = pucInput[0];
}

void CAESPrivate::keyAddRound(quint32 lRound)
{
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            //aucKeySchedule:    4*x+y
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] =
                    (quint8)((qint32)m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] ^
                             (qint32)m_pucKeySchedule[ROW_STATE_MATRIX*((lRound*ROW_STATE_MATRIX)+column)+row]);
        }
    }
}

void CAESPrivate::byteSubstitute()
{
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            // S盒生成状态矩阵
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] =
                    m_aucSBox[ 16*( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] >> 4) +
                                  ( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] & 0x0f) ];
        }
    }
}

void CAESPrivate::byteInvertSubstitube()
{
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            // 逆S盒生成状态矩阵
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] =
                    m_aucISBox[ 16*( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] >> 4) +
                                   ( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] & 0x0f) ];
        }
    }
}

void CAESPrivate::rowShift()
{
    quint8 *pucTemp = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));

    //拷贝状态矩阵到pucTemp
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

    // 行移位
    // 转换pucTemp到状态矩阵
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column =0; column < COLUMN_STATE_MATRIX; ++column )
        {
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] =
                    pucTemp[COLUMN_STATE_MATRIX*row + (column+row) % m_lBlockSize];
        }
    }

    free(pucTemp);
    pucTemp = NULL;
}

void CAESPrivate::rowInvertShift()
{
    quint8 *pucTemp = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));

    // 拷贝状态矩阵到pucTemp
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

    // 行移位逆变换
    // 转换pucTemp到状态矩阵
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column =0; column < COLUMN_STATE_MATRIX; ++column )
        {
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + (column+row) % m_lBlockSize] =
                                        pucTemp[COLUMN_STATE_MATRIX*row + column];
        }
    }

    free(pucTemp);
    pucTemp = NULL;
}

void CAESPrivate::columnMix()
{
    quint8 *pucTemp = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));

    // 拷贝状态矩阵到pucTemp
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] = m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

    // 列混淆
    // 转换pucTemp到状态矩阵
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        m_pucStateMatrix[column] =
                        (quint8)( (qint32)constantMixFunc02(pucTemp[column]) ^
                                  (qint32)constantMixFunc03(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*1 + column] =
                        (quint8)( (qint32)constantMixFunc01(pucTemp[column]) ^
                                  (qint32)constantMixFunc02(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc03(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*2 + column] =
                        (quint8)( (qint32)constantMixFunc01(pucTemp[column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc02(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc03(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*3 + column] =
                        (quint8)( (qint32)constantMixFunc03(pucTemp[column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc01(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc02(pucTemp[ROW_STATE_MATRIX*3+column]));
    }

    free(pucTemp);
    pucTemp = NULL;
}

void CAESPrivate::columnInvertMix()
{
    quint8 *pucTemp = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));

    // 拷贝状态矩阵到pucTemp
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

    // 列混淆
    // 转换pucTemp到状态矩阵
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        m_pucStateMatrix[column] =
                        (quint8)( (qint32)constantMixFunc0e(pucTemp[column]) ^
                                  (qint32)constantMixFunc0b(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc0d(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc09(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*1 + column] =
                        (quint8)( (qint32)constantMixFunc09(pucTemp[column]) ^
                                  (qint32)constantMixFunc0e(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc0b(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc0d(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*2 + column] =
                        (quint8)( (qint32)constantMixFunc0d(pucTemp[column]) ^
                                  (qint32)constantMixFunc09(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc0e(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc0b(pucTemp[ROW_STATE_MATRIX*3+column]));

        m_pucStateMatrix[ROW_STATE_MATRIX*3 + column] =
                        (quint8)( (qint32)constantMixFunc0b(pucTemp[column]) ^
                                  (qint32)constantMixFunc0d(pucTemp[ROW_STATE_MATRIX*1+column]) ^
                                  (qint32)constantMixFunc09(pucTemp[ROW_STATE_MATRIX*2+column]) ^
                                  (qint32)constantMixFunc0e(pucTemp[ROW_STATE_MATRIX*3+column]));
    }

    free(pucTemp);
    pucTemp = NULL;
}

quint8 CAESPrivate::constantMixFunc01(quint8 ucData)
{
    return ucData;
}

quint8 CAESPrivate::constantMixFunc02(quint8 ucData)
{
    if( (quint8)ucData < 0x80 )
    {
        return (quint8)(qint32)(ucData << 1);
    }
    else
    {
        return (quint8)( (qint32)(ucData << 1) ^ (qint32)(0x1b) );
    }
}

quint8 CAESPrivate::constantMixFunc03(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc02(ucData) ^ (qint32)ucData );
}

quint8 CAESPrivate::constantMixFunc09(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                            (qint32)ucData );
}

quint8 CAESPrivate::constantMixFunc0b(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc09(ucData) ^ (qint32)constantMixFunc02(ucData));
}

quint8 CAESPrivate::constantMixFunc0d(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc09(ucData) ^
                                    (qint32)constantMixFunc02(constantMixFunc02(ucData)));
}

quint8 CAESPrivate::constantMixFunc0e(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc0d(ucData) ^ (qint32)ucData ^
                                                        (qint32)constantMixFunc02(ucData));
}
