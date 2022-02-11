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

int main()
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
    const char *mgm_key = "7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char key[24] = {};
    size_t key_len = sizeof(key);

    res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);

    /* Authenticate the MGM KEY */
    res = ykpiv_authenticate(g_state, key);

    /* ECC Public Point **/
    uint8_t *point = NULL;
    size_t point_len;

    /** Generate first key */

    res = ykpiv_util_generate_key(g_state,
                                  YKPIV_KEY_AUTHENTICATION,
                                  YKPIV_ALGO_ECCP256,
                                  YKPIV_PINPOLICY_ONCE,
                                  YKPIV_TOUCHPOLICY_DEFAULT,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &point,
                                  &point_len);

    for (int i = 0; i < point_len; i++)
    {
        printf("%02x", point[i]);
    }
    printf("\n");

    /* CERTIFICATE FOR IST KEY **/

    unsigned char attest[2048] = {0};
    size_t attest_len = sizeof(attest);
    res = ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest, &attest_len);

    /***** STORE INDEX OF FIRST KEY IN KEY HISTORY OBJECT ****/

    unsigned char index1[] =
        {
            0x70,
            0x59,
            0x60,
            0x14,
            0x57,
            0x12,
            0x47,
            0x61,

        };
    size_t len = sizeof(index1);

    res = ykpiv_save_object(g_state, YKPIV_OBJ_KEY_HISTORY, index1, len);

    if (res == 0)
    {
        printf("INDEX 1 saved");
    }
    else
    {
        printf("Error saving INDEX 1 %d", res);
    }

    /*** GENERATE SECOND KEY *****/

    res = ykpiv_authenticate(g_state, key);

    if (res == 0)
    {
        printf("\nAuthentication Successful for Second Key Generation");
    }

    /* ECC Public Point **/
    uint8_t *point2 = NULL;
    size_t point_len2;

    res = ykpiv_util_generate_key(g_state,
                                  0x9c,
                                  YKPIV_ALGO_ECCP256,
                                  YKPIV_PINPOLICY_ONCE,
                                  YKPIV_TOUCHPOLICY_DEFAULT,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &point2,
                                  &point_len2);

    /******CERTIFICATE GENERATION****/

    unsigned char attest2[2048] = {0};
    size_t attest_len2 = sizeof(attest2);
    res = ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest2, &attest_len2);

    /* printf("\n\nCertificate\n");
     for(int i=0;i<attest_len2;i++)
     {
         printf("%02x", attest2[i]);
     }
     */

    /***** STORE INDEX OF SECOND  KEY IN PRINTED INFORMATION ****/

    res = ykpiv_verify(g_state, "469901", NULL);

    unsigned char index2[] =
        {
            0x70,
            0x59,
            0x60,
            0x14,
            0x57,
            0x12,
            0x47,
            0x61,

        };
    size_t len2 = sizeof(index2);

    res = ykpiv_save_object(g_state, YKPIV_OBJ_PRINTED, index2, len2);

    if (res == 0)
    {
        printf("INDEX 2 saved");
    }
    else
    {
        printf("Error saving INDEX 2 %d", res);
    }

    /**** GENERATE THE THIRD KEY *****/
    res = ykpiv_authenticate(g_state, key);

    /* ECC Public Point **/
    uint8_t *point3 = NULL;
    size_t point_len3;

    res = ykpiv_util_generate_key(g_state,
                                  0x9d,
                                  YKPIV_ALGO_ECCP256,
                                  YKPIV_PINPOLICY_ONCE,
                                  YKPIV_TOUCHPOLICY_DEFAULT,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NULL,
                                  &point3,
                                  &point_len3);

    /******CERTIFICATE GENERATION****/

    unsigned char attest3[2048] = {0};
    size_t attest_len3 = sizeof(attest2);
    res = ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest2, &attest_len2);

    /*printf("\n\nCertificate\n");
    for(int i=0;i<attest_len3;i++)
    {
        printf("%02x", attest3[i]);
    }*/

    /***** STORE INDEX OF SECOND  KEY IN PRINTED INFORMATION ****/

    res = ykpiv_verify(g_state, "469901", NULL);

    unsigned char index3[] =
        {
            0x70,
            0x59,
            0x60,
            0x14,
            0x57,
            0x12,
            0x47,
            0x61,

        };
    size_t len3 = sizeof(index2);

    res = ykpiv_save_object(g_state, YKPIV_OBJ_IRIS, index3, len3);

    if (res == 0)
    {
        printf("\n\nINDEX 3 SAVED");
    }
    else
    {
        printf("\nError SAVING INDEX 3 %d", res);
    }

    return 0;
}