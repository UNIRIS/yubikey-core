#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>

ykpiv_rc rc;
static ykpiv_state *g_state;

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

void generateKey()
{
    const char *mgm_key = "010203040506070801020304050607080102030405060708";
    unsigned char key[24];
    size_t key_len = sizeof(key);

    rc = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
    if(rc!=0)
    {
        printf("Hex decode failed, Error Code: %d\n", rc);
    }

    /* Authenticate with the MGM Key */
    rc = ykpiv_authenticate(g_state, key);
    if(rc!=0)
    {
        printf("MGM Key Verification Failed, Error Code: %d\n", rc);
    }

    /* ECC Public Key */
    uint8_t *ecc_public_key = NULL;
    size_t ecc_key_len;

    /* ECC Key Generation */
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

    for (int i = 0; i < ecc_key_len; i++)
    {
        printf("%02x", ecc_public_key[i]);
    }
    printf("\n");
}