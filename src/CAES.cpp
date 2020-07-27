#include "CAES_p.h"

#define MAX_KEY_SIZE            32
#define SIZE_KEY_SCHEDULE       16*15

#define ROW_STATE_MATRIX        4
#define COLUMN_STATE_MATRIX     4
#define SIZE_STATE_MATRIX       ROW_STATE_MATRIX*COLUMN_STATE_MATRIX

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

void CAES::AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile)
{
    char *aucInput = (char*)calloc(16, sizeof(char));
    char *aucOutput = (char*)calloc(16, sizeof(char));

    if( pOriginFile->open(QIODevice::ReadOnly)
            && pEncryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        while(!pOriginFile->atEnd())
        {
            memset(aucInput, 0, 16);
            pOriginFile->read(aucInput, 16);
            AESEncryption(aucInput, aucOutput);
            pEncryptFile->write(aucOutput, 16);
        }
    }

    pOriginFile->close();
    pEncryptFile->close();

    free(aucInput);
    aucInput = NULL;

    free(aucOutput);
    aucOutput = NULL;
}

void CAES::AESEncryptionFile(QString sOriginFileName, QString sEncryptFileName)
{
    QFile fileOrigin(sOriginFileName);
    QFile fileEncrypt(sEncryptFileName);

    this->AESEncryptionFile(&fileOrigin, &fileEncrypt);
}

void CAES::AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile)
{
    char *aucInput = (char*)calloc(16, sizeof(char));
    char *aucOutput = (char*)calloc(16, sizeof(char));

    if( pOriginFile->open(QIODevice::ReadOnly)
            && pDecryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        while(!pOriginFile->atEnd())
        {
            memset(aucInput, 0, 16);
            pOriginFile->read(aucInput, 16);
            AESDecryption(aucInput, aucOutput);
            pDecryptFile->write(aucOutput, 16);
        }
    }

    pOriginFile->close();
    pDecryptFile->close();

    free(aucInput);
    aucInput = NULL;

    free(aucOutput);
    aucOutput = NULL;
}

void CAES::AESDecryptionFile(QString sOriginFileName, QString sDecryptFileName)
{
    QFile fileOrigin(sOriginFileName);
    QFile fileDecrypt(sDecryptFileName);

    this->AESDecryptionFile(&fileOrigin, &fileDecrypt);
}

quint32 CAES::AESEncryptionString(void *pOriginData, quint32 ulDataInLength, void *pEncryptData)
{
    quint32 ulDataOutLength = 0;
    char *pucCurInBuff = (char*)pOriginData;
    char *pucCurOutBuff = (char*)pEncryptData;
    quint32 ulBlockNUm = ulDataInLength/16;
    quint32 ulLeftNum = ulDataInLength%16;

    for( quint32 i = 0; i < ulBlockNUm; ++i )
    {
        AESEncryption(pucCurInBuff, pucCurOutBuff);
        pucCurInBuff += 16;
        pucCurOutBuff += 16;
        ulDataOutLength += 16;
    }

    if( ulLeftNum )
    {
        char *ucInBuffer = (char*)calloc(16, sizeof(char));
        memcpy(ucInBuffer, pucCurInBuff, ulLeftNum);
        AESEncryption(ucInBuffer, pucCurOutBuff);
        pucCurOutBuff += 16;
        ulDataOutLength += 16;

        free(ucInBuffer);
        ucInBuffer = NULL;
    }

    //
    char *ucExtraBuff = (char*)calloc(16, sizeof(char));
    *((quint32*)ucExtraBuff) = 16 + (16 - ulLeftNum)%16;
    AESEncryption(ucExtraBuff, pucCurOutBuff);
    ulDataOutLength += 16;

    free(ucExtraBuff);
    ucExtraBuff = NULL;

    return ulDataOutLength;
}

quint32 CAES::AESDecryptionString(void *pOriginData, quint32 ulDataInLength, void *pDecryptData)
{
    quint32 ulDataOutLength= 0;
    char *pucCurInBuff = (char*)pOriginData;
    char *pucCurOutBuff = (char*)pDecryptData;
    quint32 ulBlockNum = ulDataInLength/16;
    quint32 ulLeftNum = ulDataInLength%16;
    if(ulLeftNum)
    {
        return -1;
    }
    for( quint32 i = 0; i < ulBlockNum; ++i)
    {
        AESDecryption(pucCurInBuff,pucCurOutBuff);
        pucCurInBuff += 16;
        pucCurOutBuff += 16;
        ulDataOutLength += 16;
    }

    char *pucExtraInBuff = pucCurOutBuff - 16;
    quint32 ulExtraBytes=*((quint32 *)pucExtraInBuff);
    return (ulDataOutLength-ulExtraBytes);
}

void CAES::AESEncryptionString(const QString sOriginData, QString &sEncryptData)
{
    quint32 ulDataInLength = (quint32)sOriginData.length();
    char *pOutput = (char*)calloc(ulDataInLength + 32, sizeof(char));

    quint32 ulDataOutLength = this->AESEncryptionString(sOriginData.toLatin1().data(), ulDataInLength, pOutput);
    sEncryptData = QString::fromLatin1(pOutput, ulDataOutLength);
}

void CAES::AESDecryptionString(const QString sOriginData, QString &sDecryptData)
{
    quint32 ulDataInLength = (quint32)sOriginData.length();
    char *pOutput = (char*)calloc(ulDataInLength, sizeof(char));

    quint32 ulDataOutLength = this->AESDecryptionString(sOriginData.toLatin1().data(), ulDataInLength, pOutput);
    sDecryptData = QString::fromLatin1(pOutput, ulDataOutLength);
}

void CAES::AESEncryption(char *pucOriginData, char *pucEncryptData, char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    if( pucKey )
    {
        setKey(pucKey, emKeyType);
    }
    memset(d->m_pucStateMatrix, 0, SIZE_STATE_MATRIX*sizeof(quint8));

    for( int i = 0; i < (4 * d->m_lBlockSize); ++i )
    {
        d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + i/4] = (quint8)pucOriginData[i];
    }

    d->keyAddRound(0);

    for( int round = 1; round <= (d->m_lRoundNumber - 1); ++round )
    {
        d->byteSubstitute();
        d->rowShift();
        d->columnMix();
        d->keyAddRound(round);
    }
    d->byteSubstitute();
    d->rowShift();
    d->keyAddRound(d->m_lRoundNumber);

    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        pucEncryptData[i] = (char)d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + (i/4)];
    }
}

void CAES::AESDecryption(char *pucOriginData, char *pucDecryptData, char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    if( pucKey )
    {
        setKey(pucKey, emKeyType);
    }
    memset(d->m_pucStateMatrix, 0, SIZE_STATE_MATRIX*sizeof(quint8));

    for( int i = 0; i < (4 * d->m_lBlockSize); ++i )
    {
        d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + i/4] = (quint8)pucOriginData[i];
    }

    d->keyAddRound(d->m_lRoundNumber);

    for( int round = d->m_lRoundNumber - 1; round >= 1; --round )
    {
        d->rowInvertShift();
        d->byteInvertSubstitube();
        d->keyAddRound(round);
        d->columnInvertMix();
    }
    d->rowInvertShift();
    d->byteInvertSubstitube();
    d->keyAddRound(0);

    for( int i = 0; i < (ROW_STATE_MATRIX * d->m_lBlockSize); ++i )
    {
        pucDecryptData[i] = (char)d->m_pucStateMatrix[COLUMN_STATE_MATRIX*(i%4) + (i/4)];
    }
}

void CAES::setKey(char *pucKey, AESKeyType emKeyType)
{
    Q_D(CAES);
    d->runKeyExpansion(emKeyType, (quint8*)pucKey);
}

CAESPrivate::CAESPrivate()
{
    q_ptr = NULL;
    m_pucKey = (quint8*)malloc(MAX_KEY_SIZE*sizeof(quint8));
    m_pucKeySchedule = (quint8*)malloc(SIZE_KEY_SCHEDULE*sizeof(quint8));
    m_pucStateMatrix = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));
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
        m_pucStateMatrix = NULL;
    }
}

void CAESPrivate::runKeyExpansion(AESKeyType emKeyType, quint8 *pucKey)
{
    setKeyLength(emKeyType);
    memcpy(m_pucKey, pucKey, emKeyType);
    expandKey();
}

void CAESPrivate::setKeyLength(AESKeyType emKeyType)
{
    m_lBlockSize = 4;       // block size always = 4 words = 16 bytes = 128 bits for AES_ENDECRYPT
    if ( EM_AES_128 == emKeyType)
    {
        m_lKeySize = 4;   //Key size = 4 words = 16 bytes = 128 bits
        m_lRoundNumber = 10;  // rounds for algorithm = 10
    }
    else if ( EM_AES_192 == emKeyType )
    {
        m_lKeySize = 6;   // 6 words = 24 bytes = 192 bits
        m_lRoundNumber = 12;
    }
    else if ( EM_AES_128 == emKeyType )
    {
        m_lKeySize = 8;   // 8 words = 32 bytes = 256 bits
        m_lRoundNumber = 14;
    }
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

    quint8 aucTemp[4];
    quint8 aucResultSub[4], aucResultShift[4];
    //产生密匙顺序表
    for( int row = m_lKeySize; row < m_lBlockSize * (m_lRoundNumber+1); ++row)
    {
        aucTemp[0] = m_pucKeySchedule[4*(row-1)+0];
        aucTemp[1] = m_pucKeySchedule[4*(row-1)+1];
        aucTemp[2] = m_pucKeySchedule[4*(row-1)+2];
        aucTemp[3] = m_pucKeySchedule[4*(row-1)+3];

        if( row % m_lKeySize )
        {
            //keyShift接受4字节数组并将它们向左旋转位移1位. 由于轮回次序表w[]有四列,所以RotWord会将一行w[]向左旋转位移
            keyShift(aucTemp, aucResultShift);
            //keySubstitute使用置换表Sbox,针对密匙次序表w[]的给定行执行逐字节替换
            keySubstitute(aucResultShift, aucResultSub);
            memcpy(aucTemp, aucResultSub, 4*sizeof(quint8));

            aucTemp[0] = (quint8)( (qint32)aucTemp[0] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+0] );
            aucTemp[1] = (quint8)( (qint32)aucTemp[1] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+1] );
            aucTemp[2] = (quint8)( (qint32)aucTemp[2] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+2] );
            aucTemp[3] = (quint8)( (qint32)aucTemp[3] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+3] );
        }
        else if( m_lKeySize > 6 && ( 4 == row % m_lKeySize ) )
        {
            keySubstitute(aucTemp, aucResultSub);
            memcpy(aucTemp, aucResultSub, 4*sizeof(quint8));
        }

        // m_pucKeySchedule[row] = m_pucKeySchedule[row-m_lKeySize] xor aucTemp
        m_pucKeySchedule[4*row+0] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+0] ^ (qint32)aucTemp[0] );
        m_pucKeySchedule[4*row+1] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+1] ^ (qint32)aucTemp[1] );
        m_pucKeySchedule[4*row+2] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+2] ^ (qint32)aucTemp[2] );
        m_pucKeySchedule[4*row+3] = (quint8) ( (qint32) m_pucKeySchedule[4*(row-m_lKeySize)+3] ^ (qint32)aucTemp[3] );
    }
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
            m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] =
                    m_aucISBox[ 16*( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] >> 4) +
                                   ( m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column] & 0x0f) ];
        }
    }
}

void CAESPrivate::rowShift()
{
    quint8 *pucTemp = (quint8*)malloc(SIZE_STATE_MATRIX*sizeof(quint8));

    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

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

    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

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

    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] = m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

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

    for( int row = 0; row < ROW_STATE_MATRIX; ++row )
    {
        for( int column = 0; column < COLUMN_STATE_MATRIX; ++column )
        {
            pucTemp[COLUMN_STATE_MATRIX*row + column] =
                    m_pucStateMatrix[COLUMN_STATE_MATRIX*row + column];
        }
    }

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
    //return (quint8)( (qint32)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
    //                        (qint32)constantMixFunc02(ucData) ^ (qint32)ucData );
    return (quint8)( (qint32)constantMixFunc09(ucData) ^
                                    (qint32)constantMixFunc02(ucData));
}

quint8 CAESPrivate::constantMixFunc0d(quint8 ucData)
{
    return (quint8)( (qint32)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
                           (qint32)constantMixFunc02(constantMixFunc02(ucData)) ^ (qint32)ucData );
    //return (quint8)( (qint32)constantMixFunc09(ucData) ^
    //                                (qint32)constantMixFunc02(constantMixFunc02(ucData)));
}

quint8 CAESPrivate::constantMixFunc0e(quint8 ucData)
{
    //return (quint8)( (qint32)constantMixFunc02(constantMixFunc02(constantMixFunc02(ucData))) ^
    //                        (qint32)constantMixFunc02(constantMixFunc02(ucData)) ^
    //                        (qint32)constantMixFunc02(ucData) );
    return (quint8)( (qint32)constantMixFunc0d(ucData) ^ (qint32)ucData ^
                                    (qint32)constantMixFunc02(ucData));
}
