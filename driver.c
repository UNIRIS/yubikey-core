#include <stdio.h>
#include "uniris-yubikey.h"

void main()
{
    initializeYK();
    for (int k = 10001; k > 9978; k--)
    {
        INT publicKeySize = 0;
        BYTE *ecckey = getPublicKey(k, &publicKeySize);
        for (int v = 0; v < publicKeySize; v++)
        {
            printf("%02x", ecckey[v]);
        }
        printf("\n");
    }
}