/*******************************************************************************
 *   Archethic Yubikey Library
 *   (c) 2021 Varun Deshpande, Uniris
 *
 *  Licensed under the GNU Affero General Public License, Version 3 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.gnu.org/licenses/agpl-3.0.en.html
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <stdio.h>
#include "uniris-yubikey.h"

void main()
{
    initializeYK();
    int is_connected = checkYK();
    printf("Connected: %s\n", is_connected ? "True" : "False");

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

    BYTE test_key[] = {0x04, 0xa9, 0xee, 0x8b, 0x22, 0xcb, 0xa8, 0xa0, 0x9b, 0x74, 0xfd, 0xe4, 0x5a, 0xe2, 0xfe, 0x6e, 0xd6, 0xf7, 0xca, 0xda, 0xf1, 0xf5, 0x01, 0xc5, 0xf6, 0x17, 0x0d, 0xf9, 0x08, 0x58, 0x16, 0xa8, 0xd3, 0x17, 0xae, 0xbc, 0xe2, 0x8d, 0xfe, 0x8c, 0x58, 0x97, 0xab, 0x63, 0x74, 0xf7, 0x51, 0xb8, 0x09, 0xec, 0x42, 0xa6, 0xed, 0x07, 0x4b, 0x54, 0xc3, 0x95, 0xae, 0x40, 0x48, 0x1c, 0x42, 0x08, 0xdd};
    INT eccPointLen = 0;
    BYTE *ecdhPoint;

    printf("\nArchEthic Index = %d\n", getArchEthicIndex());

    ecdhPoint = ecdhPastKey(0, test_key, &eccPointLen);
    printf("\nECDH Point (raw) = \n");
    for (int v = 0; v < eccPointLen; v++)
    {
        printf("%02x", ecdhPoint[v]);
    }
    printf("\n");

    INT certificateSize = 0;
    BYTE *certificate = getRootCertificate(&certificateSize);
    printf("\nRoot Certificate = \n");
    for (int v = 0; v < certificateSize; v++)
    {
        printf("%02x", certificate[v]);
    }
    printf("\n");
}