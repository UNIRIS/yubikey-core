/*
COMPILE : gcc test.c -lykpiv -lcrypto -o test
*/

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/des.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <ykpiv/ykpiv.h>
#include <ykpiv/ykpiv-config.h>
#include <stdlib.h>
#include <check.h>
#include <time.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

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

#define MAX_LENGTH 1024

void print_certificate(X509 *cert)
{
    char subj[MAX_LENGTH + 1];
    char issuer[MAX_LENGTH + 1];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
    printf("certificate: %s\n", subj);
    printf("\tissuer: %s\n\n", issuer);
}

void main()
{
    ykpiv_rc res;
    ykpiv_state *g_state;
    /* Intialize*/
    res = ykpiv_init(&g_state, true);
    if (res != 0)
    {
        printf("\n Initialization Unsuccessful");
    }
    /*Connect*/
    res = ykpiv_connect(g_state, NULL);
    if (res != 0)
    {
        printf("\n Connection Unsuccessful");
    }

    /* Generating the key pair  require authentication, which is done by providing the management key. */
    const char *mgm_key = "010203040506070801020304050607080102030405060708";
    unsigned char key[24] = {};
    size_t key_len = sizeof(key);

    res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);

    /* Authenticate the MGM KEY */
    res = ykpiv_authenticate(g_state, key);

    /* ECC Public Point **/
    uint8_t *point = NULL;
    size_t point_len;

    /** Key Generation */

    for (int i = 0; i < sizeof(key_slots); i++)
    {
        res = ykpiv_util_generate_key(g_state,
                                      key_slots[i],
                                      YKPIV_ALGO_ECCP256,
                                      YKPIV_PINPOLICY_NEVER,
                                      YKPIV_TOUCHPOLICY_NEVER,
                                      NULL,
                                      NULL,
                                      NULL,
                                      NULL,
                                      &point,
                                      &point_len);
        printf("%d : ", i);
        for (int i = 0; i < point_len; i++)
        {
            printf("%02x", point[i]);
        }
        printf("\n");

        /******CERTIFICATE GENERATION****/

        unsigned char attest[2048] = {0};
        size_t attest_len = sizeof(attest);
        res = ykpiv_attest(g_state, key_slots[i], attest, &attest_len);

        res = ykpiv_save_object(g_state, key_certificates[i], attest, attest_len);
        if (res == 0)
        {
            printf("Object saved\n");
        }
        else
        {
            printf("Error saving object %d\n", res);
        }

        unsigned char certi_yk[2048] = {0};
        size_t yk_attest_len = sizeof(certi_yk);
        ykpiv_fetch_object(g_state, key_certificates[i], certi_yk, &yk_attest_len);

        const unsigned char *data = certi_yk;
        X509 *cert = d2i_X509(NULL, &data, yk_attest_len);
        if (!cert)
        {
            printf("Error Parsing Certificate\n");
        }
        print_certificate(cert);
        X509_free(cert);
    }
}