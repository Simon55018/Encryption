#ifndef CAES_H
#define CAES_H

#include <QObject>
#include <QScopedPointer>

class CAESPrivate;
class CAES
{
    Q_DECLARE_PRIVATE(CAES)
    Q_DISABLE_COPY(CAES)

public:
    enum KeySize
    {
        EM_BITS_128 = 16,
        EM_BITS_192 = 24,
        EM_BITS_256 = 32,
    };

public:
    CAES();
    CAES(quint32 lKeySize, quint8 &pucKey);
    ~CAES();

private:
    QScopedPointer<CAESPrivate>     d_ptr;
};

#endif // CAES_H
