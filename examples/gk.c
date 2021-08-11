/*** KEY GENERATION
Generating a key pair will have the public key as an output (action "generate"). The public key will be used to either
generate a self signed certificate (action "selfsign") or a certificate request (action "request-certificate"). The
resulting certificate should then be imported into the same slot (action "import-certificate").

yubico-piv-tool -a generate -s <slot> -k [ -A <key algorithm> -o <public key file> ]

COMPILE : gcc gk.c -lykpiv -o gk

 **/

#include<stdio.h>
#include<string.h>
#include<openssl/ec.h>
#include<openssl/des.h>
#include<openssl/pem.h>
#include<openssl/pkcs12.h>
#include<openssl/rand.h>
#include<openssl/bn.h>
#include<openssl/rand.h>
#include<openssl/x509.h>
#include<ykpiv/ykpiv.h>
#include<ykpiv/ykpiv-config.h>
#include<stdlib.h>
#include<check.h>
#include<time.h>

int main()
{
   ykpiv_rc res;
   ykpiv_state *g_state;
   /* Intialize*/
   res = ykpiv_init(&g_state, true);
   if(res!=0)
   {
       printf("\n Initialization Unsuccessful");
   }
   /*Connect*/
   res=ykpiv_connect(g_state, NULL);
   if(res!=0)
   {
       printf("\n Connection Unsuccessful");
   }
	
	/* Generating the key pair  require authentication, which is done by providing the management key. */
    const char *mgm_key="7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char key[24]={};
    size_t key_len=sizeof(key);
    
    res=ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
     
    /* Authenticate the MGM KEY */
    res=ykpiv_authenticate(g_state, key);

    /* ECC Public Point **/
    uint8_t *point=NULL;
    size_t point_len;

    /** Key Generation */

    res=ykpiv_util_generate_key(g_state,
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

    for(int i=0;i<point_len;i++)
    {
        printf("%02x", point[i]);

    }
    printf("\n");

    /******CERTIFICATE GENERATION****/

    unsigned char attest[2048]={0};
    size_t attest_len=sizeof(attest);
    res=ykpiv_attest(g_state, YKPIV_KEY_AUTHENTICATION, attest, &attest_len);

    printf("\n\nCertificate\n");
    for(int i=0;i<attest_len;i++)
    {
        printf("%02x", attest[i]);
    }
    
  
	
    return 0;
}
