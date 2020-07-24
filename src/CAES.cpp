#include "CAES_p.h"

CAES::CAES()
    : d_ptr(new CAESPrivate)
{
    d_ptr->q_ptr = NULL;
}

CAES::CAES(quint32 lKeySize, quint8 &pucKey)
    : d_ptr(new CAESPrivate)
{
    d_ptr->q_ptr = NULL;
}

CAES::~CAES()
{

}

CAESPrivate::CAESPrivate()
{
    q_ptr = NULL;
}

CAESPrivate::~CAESPrivate()
{

}
