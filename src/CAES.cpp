#include "CAES_p.h"

CAES::CAES()
    : d_ptr(new CAESPrivate)
{
    d_ptr->q_ptr = NULL;
}

CAES::CAES(quint8 *pucKey, AESKeyType emKeyType)
    : d_ptr(new CAESPrivate)
{
    Q_D(CAES);

    d_ptr->q_ptr = NULL;

    d->m_pucKey = (quint8*)malloc(emKeyType);
    memcpy(d->m_pucKey, pucKey, emKeyType);
    d->runKeyExpansion(emKeyType, pucKey);
}

CAES::~CAES()
{
    Q_D(CAES);
    if( NULL != d->m_pucKey )
    {
        free(d->m_pucKey);
        d->m_pucKey = NULL;
    }
}

bool CAES::AESEncryptionFile(QFile *pOriginFile, QFile *pEncryptFile)
{
    quint8 aucInput[16];
    quint8 aucOutput[16];

    if( pOriginFile->open(QIODevice::ReadOnly)
            && pEncryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        while(!pOriginFile->atEnd())
        {
            memset(aucInput, 0, 16);
            pOriginFile->read(aucInput, 16);
            AESEncryption(aucInput, aucOutput);
            pEncryptFile->write(aucOutput);
        }
    }

    pOriginFile->close();
    pEncryptFile->close();
}

bool CAES::AESDecryptionFile(QFile *pOriginFile, QFile *pDecryptFile)
{
    quint8 aucInput[16];
    quint8 aucOutput[16];

    if( pOriginFile->open(QIODevice::ReadOnly)
            && pDecryptFile->open(QIODevice::WriteOnly|QIODevice::Truncate) )
    {
        while(!pOriginFile->atEnd())
        {
            memset(aucInput, 0, 16);
            pOriginFile->read(aucInput, 16);
            AESDecryption(aucInput, aucOutput);
            pDecryptFile->write(aucOutput);
        }
    }

    pOriginFile->close();
    pDecryptFile->close();
}

bool CAES::AESEncryption(quint8 *pucOriginData, quint8 *pucEncryptData, quint8 *pucKey, AESKeyType emKeyType)
{

}

bool CAES::AESDecryption(quint8 *pucOriginData, quint8 *pucDecryptData, quint8 *pucKey, AESKeyType emKeyType)
{

}

CAESPrivate::CAESPrivate()
{
    q_ptr = NULL;
    m_pucKey = NULL;
    m_pucKeySchedule = (quint8*)calloc(16*15, sizeof(quint8));
}

CAESPrivate::~CAESPrivate()
{

}

void CAESPrivate::runKeyExpansion(AESKeyType emKeyType, quint8 *pucKeyBytes)
{
    setKeyLength(emKeyType);
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
            memcpy(aucTemp, aucResultSub, strlen(aucTemp));

            aucTemp[0] = (quint8)( (qint32)aucTemp[0] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+0] );
            aucTemp[1] = (quint8)( (qint32)aucTemp[1] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+1] );
            aucTemp[2] = (quint8)( (qint32)aucTemp[2] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+2] );
            aucTemp[3] = (quint8)( (qint32)aucTemp[3] ^ (qint32) m_aucConstant[4*(row/m_lKeySize)+3] );
        }
        else if( m_lKeySize > 6 && ( 4 == row % m_lKeySize ) )
        {
            keySubstitute(aucTemp, aucResultSub);
            memcpy(aucTemp, aucResultSub, strlen(aucTemp));
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
