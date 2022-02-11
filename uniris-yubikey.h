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
#include <stdbool.h>

typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeYK();
bool checkYK();
INT getArchEthicIndex();
bool incrementIndex();

BYTE *getRootKey(INT *publicKeySize);
BYTE *getCurrentKey(INT *publicKeySize);
BYTE *getNextKey(INT *publicKeySize);
BYTE *getPastKey(INT archEthicIndex, INT *publicKeySize);

BYTE *getRootCertificate(INT *certificateSize);
BYTE *getCurrentCertificate(INT *certificateSize);
BYTE *getNextCertificate(INT *certificateSize);
BYTE *getPastCertificate(INT archEthicIndex, INT *certificateSize);

BYTE *signCurrentKey(BYTE *hashToSign, INT *eccSignSize);
BYTE *signPastKey(INT archEthicIndex, BYTE *hashToSign, INT *eccSignSize);

BYTE *ecdhCurrentKey(BYTE *euphemeralKey, INT *eccPointSize);
BYTE *ecdhPastKey(INT archEthicIndex, BYTE *euphemeralKey, INT *eccPointSize);

/*
 *
 * Internal functions, not for use
 *
 */

void verifyPinYK();
void authenticateYK();

void fetchKey(BYTE ykIndex);
void generateKey(BYTE ykIndex);
void generateCertificate(BYTE ykIndex);

BYTE getYKIndex();
void saveIndex(BYTE ykIndex, INT archEthicIndex);

void signECDSA(BYTE *hashToSign, BYTE ykIndex);
void getECDHPoint(BYTE ykIndex, BYTE *euphemeralKey);