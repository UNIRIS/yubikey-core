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
/*
    !!! Caution: This program uses internal functions of Yubikey library, provided by Uniris. !!!
    !!! Do not run this unless you are absolutely sure of what it does. You may lose access to your UCOs !!!
    This program sets/resets your (new) Yubikey. This will generate a new key + certificate on key_slot 0
    and set it as current key with ArchEthic Index 0 and will also generate a new key + certificate on
    key_slot 1 as next key with ArchEthic Index 1. Change the parameters accordingly for a customized
    setup. Compile gcc setup/setup-yubikey.c -o setup-yubikey uniris-yubikey.c -lykpiv -lcrypto
*/

#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>
#include "../uniris-yubikey.h"

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