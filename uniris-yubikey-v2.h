#include <stdbool.h>

typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeYK();
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