#ifndef CAES_P_H
#define CAES_P_H

#include "CAES.h"

class CAESPrivate
{
    Q_DECLARE_PUBLIC(CAES)
public:
    CAESPrivate();
    ~CAESPrivate();

private:
    CAES        *q_ptr;
};
#endif // CAES_P_H
