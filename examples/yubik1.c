/*******************************************************************************
 *   Archethic Yubikey Library
 *   (c) 2021 Lucy Sharma, Uniris
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

/* ABOUT DEVICE */
/* gcc yubik1.c -lykpiv -o yubik1*/

#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <ykpiv/ykpiv.h>
#include <ykpiv/ykpiv-config.h>
#include <stdlib.h>
#include <check.h>

int main()
{
    ykpiv_rc res;
    ykpiv_state *g_state;
    /* Intialize*/
    res = ykpiv_init(&g_state, true);
    if (res == 0)
    {
        printf("\nSuccessful");
    }
    /*Connect*/
    res = ykpiv_connect(g_state, NULL);
    if (res == 0)
    {
        printf("\nSuccessful connect");
    }

    /** ABOUT THE DEVICE **/
    ykpiv_devmodel model;
    char version[256] = {0};
    char reader_buf[2048] = {0};
    size_t num_readers = sizeof(reader_buf);
    res = ykpiv_get_version(g_state, version, sizeof(version));
    fprintf(stderr, "Version: %s\n", version);
    model = ykpiv_util_devicemodel(g_state);
    fprintf(stdout, "Model: %x\n", model);
    char *reader_ptr;
    res = ykpiv_list_readers(g_state, reader_buf, &num_readers);

    for (reader_ptr = reader_buf; *reader_ptr != '\0'; reader_ptr += strlen(reader_ptr) + 1)
    {
        fprintf(stdout, "FOund device %s \n", reader_ptr);
    }

    /* Read Certificate */
    uint8_t *read_cert = NULL;
    size_t read_cert_len = 0;
    const uint8_t g_cert[] = {
        "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
        "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
        "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
        "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
        "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"};

    res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t *)g_cert, sizeof(g_cert), YKPIV_CERTINFO_UNCOMPRESSED);

    res = ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert, &read_cert_len);

    for (size_t i = 0; i < read_cert_len; i++)
    {
        printf("%02x", read_cert[i]);
    }

    res = ykpiv_util_delete_cert(g_state, YKPIV_KEY_AUTHENTICATION);

    res = ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert, &read_cert_len);

    res = ykpiv_util_free(g_state, read_cert);

    /* list keys */
    ykpiv_key *keys = NULL;
    size_t data_len;
    uint8_t key_count;
    res = ykpiv_util_list_keys(g_state, &key_count, &keys, &data_len);
    printf("\nKEY COUNT %u", key_count);
    printf("\n\n KEY");

    printf("%u", keys->slot);
    printf("Key Certificate");
    for (int i = 0; i < keys->cert_len; i++)
    {
        printf("%02x", keys->cert[i]);
    }

    return 0;
}
