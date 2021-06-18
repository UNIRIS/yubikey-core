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

   const uint8_t g_cert[] = {
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
  "0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK0123456789ABCDEFGHIK"
    };

    
    uint8_t *point=NULL;
    size_t point_len;;

    res = ykpiv_util_write_cert(g_state, YKPIV_KEY_AUTHENTICATION, (uint8_t*)g_cert, sizeof(g_cert), YKPIV_CERTINFO_UNCOMPRESSED);

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

    printf("%d", res);

    return 0;
}
