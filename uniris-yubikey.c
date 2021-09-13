#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>
#include <openssl/x509.h>
#include "uniris-yubikey.h"

ykpiv_rc rc;
static ykpiv_state *g_state;

static BYTE rsa_root_key[300] = {0};
static INT rsa_key_len;

static BYTE ecc_public_key[65] = {0};
static INT ecc_key_len;

unsigned char key_slots[] = {0x82, 0x83, 0x84, 0x85,
                             0x86, 0x87, 0x88, 0x89,
                             0x8a, 0x8b, 0x8c, 0x8d,
                             0x8e, 0x8f, 0x90, 0x91,
                             0x92, 0x93, 0x94, 0x95};

unsigned int key_certificates[] = {0x5fc10d, 0x5fc10e, 0x5fc10f, 0x5fc110,
                                   0x5fc111, 0x5fc112, 0x5fc113, 0x5fc114,
                                   0x5fc115, 0x5fc116, 0x5fc117, 0x5fc118,
                                   0x5fc119, 0x5fc11a, 0x5fc11b, 0x5fc11c,
                                   0x5fc11d, 0x5fc11e, 0x5fc11f, 0x5fc120};

void initializeYK()
{
    /* Initialize */
    rc = ykpiv_init(&g_state, true);
    if (rc != 0)
    {
        printf("Initialization Failed, Error Code: %d\n", rc);
    }

    /* Connect */
    rc = ykpiv_connect(g_state, NULL);
    if (rc != 0)
    {
        printf("Connection Failed, Error Code: %d\n", rc);
    }
}

void authenticateYK()
{
    const char *mgm_key = "010203040506070801020304050607080102030405060708";
    unsigned char key[24];
    size_t key_len = sizeof(key);

    rc = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
    if (rc != 0)
    {
        printf("Hex decode failed, Error Code: %d\n", rc);
    }

    /* Authenticate with the MGM Key */
    rc = ykpiv_authenticate(g_state, key);
    if (rc != 0)
    {
        printf("MGM Key Verification Failed, Error Code: %d\n", rc);
    }
}

void generateKey(BYTE ykIndex)
{
    /* ECC Public Point **/
    uint8_t *point = NULL;
    size_t point_len;

    /* Key Generation */

    rc = ykpiv_util_generate_key(g_state,
                                 key_slots[ykIndex],
                                 YKPIV_ALGO_ECCP256,
                                 YKPIV_PINPOLICY_NEVER,
                                 YKPIV_TOUCHPOLICY_NEVER,
                                 NULL,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &point,
                                 &point_len);

    if (rc != 0)
    {
        printf("Error generating key, Error Code: %d\n", rc);
    }
    printf("Saved %d : ", ykIndex);
    for (int j = 0; j < point_len; j++)
    {
        printf("%02x", point[j]);
    }
    printf("\n");
}
void generateCertificate(BYTE ykIndex)
{
    /* Certificate Generation */

    unsigned char attest[2048] = {0};
    size_t attest_len = sizeof(attest);
    rc = ykpiv_attest(g_state, key_slots[ykIndex], attest, &attest_len);

    rc = ykpiv_save_object(g_state, key_certificates[ykIndex], attest, attest_len);
    if (rc != 0)
    {
        printf("Error saving certificate, Error Code: %d\n", rc);
    }
}
void saveIndex(BYTE ykIndex, INT archEthicIndex)
{
    unsigned char index_raw[3] = {0};

    index_raw[0] = ykIndex;
    //big endian
    index_raw[1] = archEthicIndex >> 8;
    index_raw[2] = archEthicIndex;

    rc = ykpiv_save_object(g_state, YKPIV_OBJ_KEY_HISTORY, index_raw, sizeof(index_raw));

    if (rc != 0)
    {
        printf("Error saving Index, Error Code: %d\n", rc);
    }
    printf("YK Index: %d, ArchEthic Index: %d\n", ykIndex, archEthicIndex);
}
BYTE getYKIndex()
{
    //Check why extra 2 bytes are needed?
    unsigned char index_yk[5] = {0};
    size_t index_length = sizeof(index_yk);
    rc = ykpiv_fetch_object(g_state, YKPIV_OBJ_KEY_HISTORY, index_yk, &index_length);
    if (rc != 0)
    {
        printf("Fetch Unsuccessful, Error Code: %d\n", rc);
    }
    return index_yk[0];
}

INT getArchEthicIndex()
{
    //Check why extra 2 bytes are needed?
    unsigned char index_yk[5] = {0};
    size_t index_length = sizeof(index_yk);
    rc = ykpiv_fetch_object(g_state, YKPIV_OBJ_KEY_HISTORY, index_yk, &index_length);
    if (rc != 0)
    {
        printf("Fetch Unsuccessful, Error Code: %d\n", rc);
    }
    INT archEthicIndex;

    archEthicIndex = index_yk[1] << 8;
    archEthicIndex += index_yk[2];
    return archEthicIndex;
}

void fetchKey(INT localIndex)
{
    unsigned char certi_yk[2048] = {0};
    size_t yk_attest_len = sizeof(certi_yk);
    ykpiv_fetch_object(g_state, key_certificates[localIndex], certi_yk, &yk_attest_len);

    const unsigned char *data = certi_yk;
    X509 *cert = d2i_X509(NULL, &data, yk_attest_len);
    if (!cert)
    {
        printf("Error Parsing Certificate\n");
    }

    struct asn1_string_st *mykey = X509_get0_pubkey_bitstr(cert);

    memcpy(ecc_public_key, mykey->data, mykey->length);
    memcpy(&ecc_key_len, &mykey->length, sizeof(mykey->length));
    X509_free(cert);
}

BYTE *getCurrentKey(INT *publicKeySize)
{
    INT previous_key_index = (getYKIndex() - 1 + 20) % 20;
    fetchKey(previous_key_index);
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}

BYTE *getNextKey(INT *publicKeySize)
{
    fetchKey(getYKIndex());
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}

BYTE *getPublicKey(INT keyIndex, INT *publicKeySize)
{
    INT offset = getArchEthicIndex() - keyIndex;
    if (offset > 19 || offset < 0)
        return NULL;

    INT slotPosition = (getYKIndex() - offset + 20) % 20;
    fetchKey(slotPosition);
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}

bool incrementIndex()
{
    BYTE newYKIndex = (getYKIndex() + 1) % 20;
    INT newArchEthicIndex = getArchEthicIndex() + 1;
    authenticateYK();
    generateKey(newYKIndex);
    generateCertificate(newYKIndex);
    saveIndex(newYKIndex, newArchEthicIndex);
    if (getYKIndex() == newYKIndex && getArchEthicIndex() == newArchEthicIndex)
        return true;
    else
        return false;
}

BYTE *getRootKey(INT *publicKeySize)
{
    unsigned char *pb = 0;
    size_t pblen = 0;
    ykpiv_util_read_cert(g_state, 0xf9, &pb, &pblen);

    const BYTE *data = pb;
    X509 *cert = d2i_X509(NULL, &data, pblen);
    if (!cert)
    {
        printf("Error Parsing Certificate\n");
    }

    struct asn1_string_st *mykey = X509_get0_pubkey_bitstr(cert);

    memcpy(rsa_root_key, mykey->data, mykey->length);
    memcpy(&rsa_key_len, &mykey->length, sizeof(mykey->length));
    X509_free(cert);

    memcpy(publicKeySize, &rsa_key_len, sizeof(rsa_key_len));
    return rsa_root_key;
}