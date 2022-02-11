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

/* IMPORT ACTION

COMPILE : gcc import.c -lykpiv -o import

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
#include <stddef.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/sha.h>

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

    /* Pin Verification*/
    int tries = 100;

    res = ykpiv_verify(g_state, "469901", &tries);

    // RSA2048 private key, generated with: `openssl genrsa 2048 -out private.pem`
    static const char *private_key_pem =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAwVUwmVbc+ffOy2+RivxBpgleTVN6bUa0q7jNYB+AseFQYaYq\n"
        "EGfa+VGdxSGo+8DV1KT9+fNEd5243gXn/tcjtMItKeB+oAQc64s9lIFlYuR8bpq1\n"
        "ibr33iW2elnnv9mpecqohdCVwM2McWveoPyb7MwlwVuhqexOzJO29bqJcazLbtkf\n"
        "ZETK0oBx53/ylA4Y6nE9Pa46jW2qhj+KShf1iBg+gAyt3eI+wI2Wmub1WxLLH8D2\n"
        "w+kow8QhQOa8dHCkRRw771JxVO5+d+Y/Y+x9B1HgF4q0q9xUlhWLK2TR4ChBFzXe\n"
        "47sAHsSqi/pl5JbwYrHPOE/VEBLukmjL8NFCSQIDAQABAoIBADmEyOK2DyRnb6Ti\n"
        "2qBJEJb/boj+7wuX36S/ZIrWlIlXiXyj3RvoaiOG/rNpokbURknvlIhKsfIMgLW9\n"
        "eBo/k6Xxp1IwMjwVPS1uzbFjFfDoHYUijiQd9iSnf7TDDsnrThqoCp9VQViNTt1n\n"
        "xGKNBS7cRddTFbPiVEdVIzfUeZPR2oRrc4maBCRCrQgg8WNknawmc8zhkf2NiPj3\n"
        "tWLQHMy1/MgW2W1LM9sgzllEtS5CZUnyGy2HbbhS2tbZ6j9kPzOp0pPxxTTzJmmV\n"
        "fi1vkJcVW4+MdXjWmhALcPA4dO7Y2Ljiu6VxIxQORRO1DyiCjAs1AVMQxgPAAY41\n"
        "YR4Q2EkCgYEA4zE0oytg97aVaBY9CKi7/PqR+NI/uEvfoQCnT+ddaJgp/qsspuXo\n"
        "tJt94p13ANd8O7suqQTVNvbZq1rX10xQjJZ9nvlqQa6iHkN6Epq31XBK3Z+acjIV\n"
        "A2rAgKBByjz9/CpKHqnOsrTWU1Y7x416IG4BZt42hHdrxRH98/wiDH8CgYEA2djj\n"
        "AjwgK+MwDnshwT1NNgCSP/2ZHatBAykZ5BCs9BJ6MNYqqXVGYoqs5Z5kSkow+Db3\n"
        "pipkEieo5w2Rd5zkolTThaVCvRkSe5wRiBpZhaeY+b0UFwavGCb6zU/MmJIMDPiI\n"
        "2iRGeCXgQDvIS/icIqzbTtp6dZaoMgG7LdSR7TcCgYBtxGhaLas8A8tL7vKuLFgn\n"
        "cij0vyBqOr5hW596y54l2t7vXGTGfm5gVIAN7WaB0ZsEgPuaTet2Eu44DDwcmZKR\n"
        "WmR3Wqor8eQCGzfvpTEMvqRtT5+fbPMaI4m+m68ttyo/m28UQZbMYPLscM2RLJnE\n"
        "8WFcAiD0/33iST8ZksggoQKBgQDE/7Yhsj+hkHxHzB+1QPtOp2uaBHnvc4uCESwB\n"
        "qvbMbN0kxrejsJLqz98UcozdBYSNIiAHmvQN2uGJuCJhGXdEORNjGxRkLoUhVPwh\n"
        "qTplfC8BQHQncnrqi21oNw6ctg3BuQsAwaccRZwqWiWCVhrT3J8iCr6NEaWeOySK\n"
        "iF1CNwKBgQCRpkkZArlccwS0kMvkK+tQ1rG2xWm7c05G34gP/g6dHFRy0gPNMyvi\n"
        "SkiLTJmQIEZSAEiq0FFgcVwM6o556ftvQZuwDp5rHUbwqnHCpMJKpD9aJpStvfPi\n"
        "4p9JbYdaGqnq4eoNKemmGnbUof0dR9Zr0lGmcMTwwzBib+4E1d7soA==\n"
        "-----END RSA PRIVATE KEY-----\n";

    // Certificate signed with key above:
    // `openssl req -x509 -key private.pem -out cert.pem -subj "/CN=bar/OU=test/O=example.com/" -new`
    static const char *certificate_pem =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIC5zCCAc+gAwIBAgIJAOq8A/cmpxF5MA0GCSqGSIb3DQEBCwUAMDMxDDAKBgNV\n"
        "BAMMA2JhcjENMAsGA1UECwwEdGVzdDEUMBIGA1UECgwLZXhhbXBsZS5jb20wHhcN\n"
        "MTcwODAzMTE1MDI2WhcNMTgwODAzMTE1MDI2WjAzMQwwCgYDVQQDDANiYXIxDTAL\n"
        "BgNVBAsMBHRlc3QxFDASBgNVBAoMC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0B\n"
        "AQEFAAOCAQ8AMIIBCgKCAQEAwVUwmVbc+ffOy2+RivxBpgleTVN6bUa0q7jNYB+A\n"
        "seFQYaYqEGfa+VGdxSGo+8DV1KT9+fNEd5243gXn/tcjtMItKeB+oAQc64s9lIFl\n"
        "YuR8bpq1ibr33iW2elnnv9mpecqohdCVwM2McWveoPyb7MwlwVuhqexOzJO29bqJ\n"
        "cazLbtkfZETK0oBx53/ylA4Y6nE9Pa46jW2qhj+KShf1iBg+gAyt3eI+wI2Wmub1\n"
        "WxLLH8D2w+kow8QhQOa8dHCkRRw771JxVO5+d+Y/Y+x9B1HgF4q0q9xUlhWLK2TR\n"
        "4ChBFzXe47sAHsSqi/pl5JbwYrHPOE/VEBLukmjL8NFCSQIDAQABMA0GCSqGSIb3\n"
        "DQEBCwUAA4IBAQCamrwdEhNmY2GCQWq6U90Q3XQT6w0HHW/JmtuGeF+BTpVr12gN\n"
        "/UvEXTo9geWbGcCTjaMMURTa7mUjVUIttIWEVHZMKqBuvsUM1RcuOEX/vitaJJ8K\n"
        "Sw4upjCNa3ZxUXmSA1FBixZgDzFqjEeSiaJjMU0yX5W2p1T4iNYtF3YqzMF5AWSI\n"
        "qCO7gP5ezPyg5kDnrO3V7DBgnDiqawq7Pyn9DynKNULX/hc1yls/R+ebb2u8Z+h5\n"
        "W4YXbzGZb8qdT27qIZaHD638tL6liLkI6UE4KCXH8X8e3fqdbmqvwrq403nOGmsP\n"
        "cbJb2PEXibNEQG234riKxm7x7vNDLL79Jwtc\n"
        "-----END CERTIFICATE-----\n";

    EVP_PKEY *private_key = NULL;
    BIO *bio = NULL;
    RSA *rsa_private_key = NULL;
    unsigned char e[4] = {0};
    unsigned char p[128] = {0};
    unsigned char q[128] = {0};
    unsigned char dmp1[128] = {0};
    unsigned char dmq1[128] = {0};
    unsigned char iqmp[128] = {0};
    int element_len = 128;
    const BIGNUM *bn_e, *bn_p, *bn_q, *bn_dmp1, *bn_dmq1, *bn_iqmp;

    bio = BIO_new_mem_buf(private_key_pem, strlen(private_key_pem));
    private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    rsa_private_key = EVP_PKEY_get1_RSA(private_key);

    RSA_get0_key(rsa_private_key, NULL, &bn_e, NULL);
    RSA_get0_factors(rsa_private_key, &bn_p, &bn_q);
    RSA_get0_crt_params(rsa_private_key, &bn_dmp1, &bn_dmq1, &bn_iqmp);

    /*Authenticate before Importing*/
    const char *mgm_key = "7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char key[24] = {};
    size_t key_len = sizeof(key);

    res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);

    res = ykpiv_authenticate(g_state, key);

    if (res == 0)
    {
        printf("\nAuthenticated");
    }

    /* IMPORT KEY*/
    res = ykpiv_import_private_key(g_state,
                                   0x82,
                                   YKPIV_ALGO_RSA2048,
                                   p, element_len,
                                   q, element_len,
                                   dmp1, element_len,
                                   dmq1, element_len,
                                   iqmp, element_len,
                                   NULL, 0,
                                   YKPIV_PINPOLICY_ALWAYS, YKPIV_TOUCHPOLICY_DEFAULT);
    if (res == 0)
    {
        printf("Import Successful");
    }
    else
    {
        printf("IMport Unsucessful %d", res);
    }
}
