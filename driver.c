#include <stdio.h>
#include "uniris-yubikey.h"

void main()
{
    initializeYK();

    INT publicKeySize = 0;
    BYTE *ecckey = getCurrentKey(&publicKeySize);
    printf("\nCurrent Key = \n");
    for (int v = 0; v < publicKeySize; v++)
    {
        printf("%02x", ecckey[v]);
    }
    printf("\n");

    BYTE hash256[32] = {0x54, 0xc1, 0xa8, 0x30, 0xfa, 0xfd, 0x24, 0xd5, 0xe8, 0xec, 0xe4, 0x32, 0xbd, 0x6e, 0x67, 0xd8, 0xa0, 0xe6, 0x93, 0x05, 0x3b, 0x9f, 0x0d, 0x3b, 0xed, 0x16, 0xc9, 0x10, 0xb6, 0x2c, 0xb8, 0xe9};
    INT signLen = 0;
    BYTE *eccSign;

    eccSign = signCurrentKey(hash256, &signLen);
    printf("\nECC Sign (ASN.1 DER) = \n");
    for (int v = 0; v < signLen; v++)
    {
        printf("%02x", eccSign[v]);
    }
    printf("\n");
}