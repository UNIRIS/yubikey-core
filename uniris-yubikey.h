#include <stdbool.h>

typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeYK();
INT getArchEthicIndex();
bool incrementIndex();

BYTE *getRootKey(INT *publicKeySize);
BYTE *getCurrentKey(INT *publicKeySize);
BYTE *getNextKey(INT *publicKeySize);
BYTE *getPublicKey(INT archEthicIndex, INT *publicKeySize);

BYTE *getRootCertificate(INT *certificateSize);
BYTE *getCurrentCertificate(INT *certificateSize);
BYTE *getNextCertificate(INT *certificateSize);
BYTE *getPastCertificate(INT archEthicIndex, INT *certificateSize);

BYTE *signCurrentKey(BYTE *hashToSign, INT *eccSignSize);
BYTE *signPastKey(INT archEthicIndex, BYTE *hashToSign, INT *eccSignSize);

BYTE *ecdhCurrentKey(BYTE *euphemeralKey, INT *eccPointSize);
BYTE *ecdhPastKey(INT archEthicIndex, BYTE *euphemeralKey, INT *eccPointSize);