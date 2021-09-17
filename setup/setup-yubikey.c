/*
    !!! Caution: This program uses internal functions of Yubikey library, provided by ArchEthic. !!!
    !!! Do not run this unless you are absolutely sure of what it does. You may lose access to your UCOs !!!
    This program sets/resets your (new) Yubikey. This will generate a new key + certificate on key_slot 0
    and set it as current key with ArchEthic Index 0 and will also generate a new key + certificate on
    key_slot 1 as next key with ArchEthic Index 1. Change the parameters accordingly for a customized
    setup. Compile gcc setup-yubikey.c -lykpiv -o setup-yubikey
*/

#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>
#include "uniris-yubikey.h"

/* Caution: Internal Function Usage */
void main()
{
    /* Initialize and Authenticate */
    initializeYK();
    authenticateYK();

    /* Set Yubikey's next_key Index to 1
       Set ArchEthic's next_key Index to 1 */
    saveIndex(1, 1);

    /* Generate Key+Certificate for slot 0 (0x82) of Yubikey */
    generateKey(0);
    generateCertificate(0);

    /* Generate Key+Certificate for slot 1 (0x83) of Yubikey */
    generateKey(1);
    generateCertificate(1);
}