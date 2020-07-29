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

CAES::CAES(quint8 *pucKey, AESKeyType emKeyType)
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
    quint8 *aucInput = (quint8*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(quint8));
    quint8 *aucOutput = (quint8*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(quint8));

    // 源文件只读打开,加密文件只写打开并重头开始写入
    if( pOriginFile->open(QIODevice::ReadOnly)
            && pEncryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // 循环读取源文件,直到文件末尾
        while(!pOriginFile->atEnd())
        {
            // 每次读取16位, 因为加密操作每次只能操作16位
            pOriginFile->read((char*)aucInput, NUMBER_ENCRYPTION);
            d->AESEncryption(aucInput, aucOutput);
            // 将加密字符串写入
            pEncryptFile->write((char*)aucOutput);

            // 重置内存
            memset(aucInput, 0, SIZE_ENCRYPT_MALLOC*sizeof(quint8));
            memset(aucOutput, 0, SIZE_ENCRYPT_MALLOC*sizeof(quint8));
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
    quint8 *aucInput = (quint8*)calloc(SIZE_DECRYPT_MALLOC, sizeof(quint8));
    quint8 *aucOutput = (quint8*)calloc(SIZE_DECRYPT_MALLOC, sizeof(quint8));

    // 源文件只读打开,解密文件只写打开并重头开始写入
    if( pOriginFile->open(QIODevice::ReadOnly)
            && pDecryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        // 循环读取源文件,直到文件末尾
        while(!pOriginFile->atEnd())
        {
            // 每次读取16位, 因为解密操作每次只能操作16位
            pOriginFile->read((char*)aucInput, NUMBER_DECRYPTION);
            d->AESDecryption(aucInput, aucOutput);
            // 将解密字符串写入
            pDecryptFile->write((char*)aucOutput);

            // 重置内存
            memset(aucInput, 0, SIZE_DECRYPT_MALLOC*sizeof(quint8));
            memset(aucOutput, 0, SIZE_DECRYPT_MALLOC*sizeof(quint8));
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

quint32 CAES::AESEncryptionString(void *pOriginData, quint32 ulDataInLength, void *pEncryptData)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType)
            || NULL == pOriginData || NULL == pEncryptData )
    {
        return -1;
    }

    quint32 ulDataOutLength = 0;
    quint8 *pucCurInBuff = (quint8*)pOriginData;
    quint8 *pucCurOutBuff = (quint8*)pEncryptData;
    // 每块空间为16位,每次只操作一块空间
    quint32 ulBlockNUm = ulDataInLength / NUMBER_ENCRYPTION;
    // 超出16的倍数的字符串个数
    quint32 ulLeftNum = ulDataInLength % NUMBER_ENCRYPTION;

    // 按块操作
    for( quint32 i = 0; i < ulBlockNUm; ++i )
    {
        d->AESEncryption(pucCurInBuff, pucCurOutBuff);
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
        quint8 *ucInBuffer = (quint8*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(quint8));
        // 赋最后ulLeftNum个char值
        memcpy(ucInBuffer, pucCurInBuff, ulLeftNum);
        d->AESEncryption(ucInBuffer, pucCurOutBuff);
        // 移位16个字符
        pucCurOutBuff += NUMBER_ENCRYPTION;
        // 记录操作字符长度
        ulDataOutLength += NUMBER_ENCRYPTION;

        // 释放内存
        free(ucInBuffer);
        ucInBuffer = NULL;
    }

    // 申请额外字符空间
    quint8 *ucExtraBuff = (quint8*)calloc(SIZE_ENCRYPT_MALLOC, sizeof(quint8));
    // 计算出额外字符个数,作为加密数据
    *((quint32*)ucExtraBuff) = NUMBER_ENCRYPTION +
                                (NUMBER_ENCRYPTION - ulLeftNum)%NUMBER_ENCRYPTION;
    // 加密操作
    d->AESEncryption(ucExtraBuff, pucCurOutBuff);
    // 记录操作字符长度
    ulDataOutLength += NUMBER_ENCRYPTION;

    // 释放内存
    free(ucExtraBuff);
    ucExtraBuff = NULL;

    return ulDataOutLength;
}

quint32 CAES::AESDecryptionString(void *pOriginData, quint32 ulDataInLength, void *pDecryptData)
{
    Q_D(CAES);
    // 若设置的密钥类型错误,运行会出错,所以直接返回错误
    if( !d->checkAESType(d->m_emKeyType)
            || NULL == pOriginData || NULL == pDecryptData )
    {
        return -1;
    }

    quint32 ulDataOutLength= 0;
    quint8 *pucCurInBuff = (quint8*)pOriginData;
    quint8 *pucCurOutBuff = (quint8*)pDecryptData;
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
        d->AESDecryption(pucCurInBuff,pucCurOutBuff);
        // 每次移位16个字符
        pucCurInBuff += NUMBER_DECRYPTION;
        pucCurOutBuff += NUMBER_DECRYPTION;
        // 记录操作字符长度
        ulDataOutLength += NUMBER_DECRYPTION;
    }

    // 解密字符串最后16位为额外字符串
    quint8 *pucExtraInBuff = pucCurOutBuff - NUMBER_DECRYPTION;
    // 算出额外字符串的长度
    quint32 ulExtraBytes=*((quint32 *)pucExtraInBuff);

    // 返回正确数据长度
    return (ulDataOutLength-ulExtraBytes);
}

bool CAES::setKey(quint8 *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    d->m_emKeyType = emKeyType;
    // 密钥初始化
    bool bRet = d->runKeyExpansion(emKeyType, pucKey);

    return bRet;
}

CAESPrivate::CAESPrivate()
{
    q_ptr = NULL;

    memset(m_aucKey, 0, MAX_KEY_SIZE*sizeof(quint8));
    memset(m_aucKeySchedule, 0, SIZE_KEY_SCHEDULE*sizeof(quint8));
    memset(m_aucStateMatrix, 0, SIZE_STATE_MATRIX*sizeof(quint8));
}

CAESPrivate::~CAESPrivate()
{

}


void CAESPrivate::AESEncryption(quint8 *pucOriginData, quint8 *pucEncryptData)
{
    // 重置状态矩阵数据
    memset(&m_aucStateMatrix[0][0], 0, SIZE_STATE_MATRIX*sizeof(quint8));

    // 对状态矩阵赋原始值
    for( int i = 0; i < (4 * m_lBlockSize); ++i )
    {
        m_aucStateMatrix[i % 4][i / 4] = (quint8)pucOriginData[i];
    }

    // 密钥轮加函数0轮
    keyAddRound(0);

    for( int round = 1; round <= (m_lRoundNumber - 1); ++round )
    {
        // 字节代换
        byteSubstitute();
        // 行移位
        rowShift();
        // 列混淆
        columnMix();
        // 密钥轮加
        keyAddRound(round);
    }
    // 字节代换
    byteSubstitute();
    // 行移位
    rowShift();
    // 密钥轮加
    keyAddRound(m_lRoundNumber);

    // 获取加密后信息
    for( int i = 0; i < (ROW_STATE_MATRIX * this->m_lBlockSize); ++i )
    {
        pucEncryptData[i] = m_aucStateMatrix[i % 4][i / 4];
    }
}

void CAESPrivate::AESDecryption(quint8 *pucOriginData, quint8 *pucDecryptData)
{
    // 重置状态矩阵数据
    memset(&m_aucStateMatrix[0][0], 0, SIZE_STATE_MATRIX*sizeof(quint8));

    // 对状态矩阵赋原始值
    for (int i = 0; i < (4 * m_lBlockSize); ++i )
    {
        m_aucStateMatrix[i % 4][ i / 4] = pucOriginData[i];
    }

    // 密钥轮加
    keyAddRound(m_lRoundNumber);

    for (int round = m_lRoundNumber-1; round >= 1; --round)
    {
        // 行移位逆变换
        rowInvertShift();
        // 字节代换逆变换
        byteInvertSubstitube();
        // 密钥轮加
        keyAddRound(round);
        // 列混淆逆变换
        columnInvertMix();
    }
    // 行移位逆变换
    rowInvertShift();
    // 字节代换逆变换
    byteInvertSubstitube();
    // 密钥轮加
    keyAddRound(0);

    // 获取解密后信息
    for (int i = 0; i < (4 * m_lBlockSize); i++)
    {
        pucDecryptData[i] =  m_aucStateMatrix[i % 4][ i / 4];
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

    memcpy(m_aucKey, pucKey, emKeyType);
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
    memset(m_aucKeySchedule, 0, SIZE_KEY_SCHEDULE*sizeof(quint8));
    for( int row=0; row < m_lKeySize; ++row )       //拷贝seed 密钥
    {
        m_aucKeySchedule[4*row+0] =  m_aucKey[4*row];
        m_aucKeySchedule[4*row+1] =  m_aucKey[4*row+1];
        m_aucKeySchedule[4*row+2] =  m_aucKey[4*row+2];
        m_aucKeySchedule[4*row+3] =  m_aucKey[4*row+3];
    }

    quint8* pucTemp = new quint8[4];
    quint8* pucOutput = new quint8[4];
    for( int row = m_lKeySize; row < 4*(m_lRoundNumber+1); ++row )
    {
        pucTemp[0]=m_aucKeySchedule[4*row-4];       //当前列的前一列
        pucTemp[1]=m_aucKeySchedule[4*row-3];
        pucTemp[2]=m_aucKeySchedule[4*row-2];
        pucTemp[3]=m_aucKeySchedule[4*row-1];
        if(row%m_lKeySize==0)                       //逢nk时，对当前列的前一列作特殊处理
        {
            keyShift(pucTemp, pucOutput);
            keySubstitute(pucOutput, pucTemp);      //先移位，再代换，最后和轮常量异或
            pucTemp[0] = (quint8)( (int)pucTemp[0] ^ (int) m_aucConstant[4*(row/m_lKeySize)+0] );
            pucTemp[1] = (quint8)( (int)pucTemp[1] ^ (int) m_aucConstant[4*(row/m_lKeySize)+1] );
            pucTemp[2] = (quint8)( (int)pucTemp[2] ^ (int) m_aucConstant[4*(row/m_lKeySize)+2] );
            pucTemp[3] = (quint8)( (int)pucTemp[3] ^ (int) m_aucConstant[4*(row/m_lKeySize)+3] );
        }
        else if ( m_lKeySize > 6 && (row % m_lKeySize == 4) )
        {
            keySubstitute(pucTemp, pucOutput);
            memcpy(pucTemp, pucOutput, 4);
        }

        // m_aucKeySchedule[row] = m_aucKeySchedule[row-m_lKeySize] xor pucTemp
        m_aucKeySchedule[4*row+0] = (quint8) ( (int) m_aucKeySchedule[4*(row-m_lKeySize)+0] ^ (int)pucTemp[0] );
        m_aucKeySchedule[4*row+1] = (quint8) ( (int) m_aucKeySchedule[4*(row-m_lKeySize)+1] ^ (int)pucTemp[1] );
        m_aucKeySchedule[4*row+2] = (quint8) ( (int) m_aucKeySchedule[4*(row-m_lKeySize)+2] ^ (int)pucTemp[2] );
        m_aucKeySchedule[4*row+3] = (quint8) ( (int) m_aucKeySchedule[4*(row-m_lKeySize)+3] ^ (int)pucTemp[3] );
    }  // for loop

    delete pucTemp;
    pucTemp = NULL;

    delete pucOutput;
    pucOutput = NULL;
}

void CAESPrivate::keySubstitute(quint8 *pucInput, quint8 *pucOutput)
{
    for(int i = 0; i < 4; ++i)
    {
        pucOutput[i] = m_aucSBox[16*(pucInput[i] >> 4)+(pucInput[i] & 0x0f)];  //实际上也可以写成AesSbox[[i]];因为两者相等
    }}

void CAESPrivate::keyShift(quint8 *pucInput, quint8 *pucOutput)
{
    pucOutput[0] = pucInput[1];
    pucOutput[1] = pucInput[2];
    pucOutput[2] = pucInput[3];
    pucOutput[3] = pucInput[0];
}

void CAESPrivate::keyAddRound(quint32 lRound)
{
    //因为密钥w是一列一列排列的,即 k0 k4 k8  k12
    //						  k1 k5 k9  k13
    //						  k2 k6 k10 k14
    //						  k3 k7 k11 k15
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            // 所以i行j列的下标是4*((round*4)+column)+i即16*round+4*column+row
            m_aucStateMatrix[row][column]=(quint8)((int)m_aucStateMatrix[row][column]^(int)m_aucKeySchedule[4*((lRound*4)+column)+row]);
        }
    }
}

void CAESPrivate::byteSubstitute()
{
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            // S盒生成状态矩阵
            m_aucStateMatrix[row][column] = m_aucSBox[m_aucStateMatrix[row][column]];
            // 因为 16*(m_aucStateMatrix[row][column]>>4)+m_aucStateMatrix[row][column]&0x0f=m_aucStateMatrix[row][column]
        }
    }
}

void CAESPrivate::byteInvertSubstitube()
{
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            // 逆S盒生成状态矩阵
            m_aucStateMatrix[row][column] = m_aucISBox[m_aucStateMatrix[row][column]];
        }
    }
}

void CAESPrivate::rowShift()
{
    quint8 *pucTemp = new quint8[SIZE_STATE_MATRIX];                                        //Page105

    //拷贝状态矩阵到pucTemp
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            pucTemp[4*row+column] = m_aucStateMatrix[row][column];
        }
    }

    // 行移位
    // 转换pucTemp到状态矩阵
    for( int row = 1; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            //if(row==1)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+1)%4];					//第一行左移1位
            //else if(row==2)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+2)%4];				//第二行左移2位
            //else if(row==3)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+3)%4];				//第三行左移3位
            m_aucStateMatrix[row][column] = pucTemp[4*row+(column+row)%4];
        }
    }

    delete pucTemp;
    pucTemp = NULL;
}

void CAESPrivate::rowInvertShift()
{
    quint8 *pucTemp = new quint8[SIZE_STATE_MATRIX];

    // 拷贝状态矩阵到pucTemp
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            pucTemp[4*row+column] = m_aucStateMatrix[row][column];
        }
    }

    // 行移位逆变换
    // 转换pucTemp到状态矩阵
    for( int row = 1; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            //if(row==1)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+3)%4];			//第一行右移1位 column-1+4=column+3
            //else if(row==2)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+2)%4];		//第二行右移2位 column-2+4=column+2
            //else if(row==3)m_aucStateMatrix[row][column]=pucTemp[4*row+(column+1)%4];		//第三行右移3位 column-3+4=column+2
            m_aucStateMatrix[row][column] = pucTemp[4*row+(column-row+4)%4];
        }
    }

    delete pucTemp;
    pucTemp = NULL;
}

void CAESPrivate::columnMix()
{
    quint8 *pucTemp = new quint8[SIZE_STATE_MATRIX];

    // 拷贝状态矩阵到pucTemp
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        for( int row = 0; row < ROW_STATE_MATRIX; ++row )
        {
            pucTemp[4*row+column]=m_aucStateMatrix[row][column];
        }
    }

    // 列混淆
    //  2 3 1 1  列混淆矩阵
    //  1 2 3 1
    //  1 1 2 3
    //  3 1 1 2
    // 转换pucTemp到状态矩阵
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        m_aucStateMatrix[0][column] = (quint8) ( (int)constantMixFunc02(pucTemp[0+column]) ^
                                                 (int)constantMixFunc03(pucTemp[4*1+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*3+column]) );

        m_aucStateMatrix[1][column] = (quint8) ( (int)constantMixFunc01(pucTemp[0+column]) ^
                                                 (int)constantMixFunc02(pucTemp[4*1+column]) ^
                                                 (int)constantMixFunc03(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*3+column]) );

        m_aucStateMatrix[2][column] = (quint8) ( (int)constantMixFunc01(pucTemp[0+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*1+column]) ^
                                                 (int)constantMixFunc02(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc03(pucTemp[4*3+column]) );

        m_aucStateMatrix[3][column] = (quint8) ( (int)constantMixFunc03(pucTemp[0+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*1+column]) ^
                                                 (int)constantMixFunc01(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc02(pucTemp[4*3+column]) );
    }

    delete pucTemp;
    pucTemp = NULL;
}

void CAESPrivate::columnInvertMix()
{
    quint8 *pucTemp = new quint8[SIZE_STATE_MATRIX];

    // 拷贝状态矩阵到pucTemp
    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[4*row+column] =  m_aucStateMatrix[row][column];
        }
    }

    // 列混淆
    // 0e 0b 0d 09   逆变换矩
    // 09 0e 0b 0d
    // 0d 09 0e 0b
    // 0b 0d 09 0e
    // 转换pucTemp到状态矩阵
    for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
    {
        m_aucStateMatrix[0][column] = (quint8) ( (int)constantMixFunc0e(pucTemp[column]) ^
                                                 (int)constantMixFunc0b(pucTemp[4+column]) ^
                                                 (int)constantMixFunc0d(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc09(pucTemp[4*3+column]) );

        m_aucStateMatrix[1][column] = (quint8) ( (int)constantMixFunc09(pucTemp[column]) ^
                                                 (int)constantMixFunc0e(pucTemp[4+column]) ^
                                                 (int)constantMixFunc0b(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc0d(pucTemp[4*3+column]) );

        m_aucStateMatrix[2][column] = (quint8) ( (int)constantMixFunc0d(pucTemp[column]) ^
                                                 (int)constantMixFunc09(pucTemp[4+column]) ^
                                                 (int)constantMixFunc0e(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc0b(pucTemp[4*3+column]) );

        m_aucStateMatrix[3][column] = (quint8) ( (int)constantMixFunc0b(pucTemp[column]) ^
                                                 (int)constantMixFunc0d(pucTemp[4+column]) ^
                                                 (int)constantMixFunc09(pucTemp[4*2+column]) ^
                                                 (int)constantMixFunc0e(pucTemp[4*3+column]) );
    }

    delete pucTemp;
    pucTemp = NULL;
}

quint8 CAESPrivate::constantMixFunc01(quint8 ucData)
{
    return ucData;
}
quint8 CAESPrivate::constantMixFunc02(quint8 ucData)
{
    if (ucData < 0x80)
        return (quint8)(int)(ucData <<1);
    else
        return (quint8)( (int)(ucData << 1) ^ (int)(0x1b) );
}

quint8 CAESPrivate::constantMixFunc03(quint8 ucData)
{
    return (quint8) ( (int)constantMixFunc02(ucData) ^ (int)ucData );
}

quint8 CAESPrivate::constantMixFunc09(quint8 ucData)
{
    return (quint8)( (int)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                     (int)ucData );
}

quint8 CAESPrivate::constantMixFunc0b(quint8 ucData)
{
    return (quint8)( (int)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                     (int)constantMixFunc02(ucData) ^
                     (int)ucData );
}

quint8 CAESPrivate::constantMixFunc0d(quint8 ucData)
{
    return (quint8)( (int)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                     (int)constantMixFunc02(constantMixFunc02(ucData)) ^
                     (int)(ucData) );
}

quint8 CAESPrivate::constantMixFunc0e(quint8 ucData)
{
    return (quint8)( (int)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                     (int)constantMixFunc02(constantMixFunc02(ucData)) ^
                     (int)constantMixFunc02(ucData) );
}

