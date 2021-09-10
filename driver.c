#include <stdio.h>
#include "uniris-yubikey.h"

void main()
{
    initializeYK();

    INT publicKeySize = 0;
    BYTE *ecckey = getNextKey(&publicKeySize);
    for (int v = 0; v < publicKeySize; v++)
    {
        printf("%02x", ecckey[v]);
    }
    printf("\n");
}