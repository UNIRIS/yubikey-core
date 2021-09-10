#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>
#include <openssl/x509.h>
#include "uniris-yubikey.h"

ykpiv_rc rc;
static ykpiv_state *g_state;
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

/*
BYTE *generateKey(INT *publicKeySize)
{
    const char *mgm_key = "010203040506070801020304050607080102030405060708";
    unsigned char key[24];
    size_t key_len = sizeof(key);

    rc = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
    if(rc!=0)
    {
        printf("Hex decode failed, Error Code: %d\n", rc);
    }

    // Authenticate with the MGM Key
    rc = ykpiv_authenticate(g_state, key);
    if(rc!=0)
    {
        printf("MGM Key Verification Failed, Error Code: %d\n", rc);
    }

    // ECC Key Generation
    rc = ykpiv_util_generate_key(g_state,
                                  YKPIV_KEY_AUTHENTICATION,
                                  YKPIV_ALGO_ECCP256,
                                  YKPIV_PINPOLICY_NEVER,
                                  YKPIV_TOUCHPOLICY_NEVER,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &ecc_public_key,
                                  &ecc_key_len);

    if(rc!=0)
    {
        printf("ECC Key Generation Failed, Error Code: %d\n", rc);
    }
    
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}
*/

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
void getKey(INT localIndex)
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
    getKey(previous_key_index);
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}

BYTE *getNextKey(INT *publicKeySize)
{
    getKey(getYKIndex());
    memcpy(publicKeySize, &ecc_key_len, sizeof(ecc_key_len));
    return ecc_public_key;
}
