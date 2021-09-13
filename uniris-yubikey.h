typedef unsigned char BYTE;
typedef unsigned short INT;

void initializeYK();

BYTE *getCurrentKey(INT *publicKeySize);
BYTE *getNextKey(INT *publicKeySize);
BYTE *getPublicKey(INT keyIndex, INT *publicKeySize);