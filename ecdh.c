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

void main()
{
   ykpiv_rc res;
   ykpiv_state *g_state;
   
   /* Intialize*/
   res = ykpiv_init(&g_state, true);
   if(res!=0)
   {
       printf("Initialization Failed, Error Code: %d\n", res);
   }
   
   /*Connect*/
   res=ykpiv_connect(g_state, NULL);
   if(res!=0)
   {
       printf("Connection Failed, Error Code: %d\n", res);
   }

  /* PIN verification before ECDH  Exchange*/
    int tries=100;
    res=ykpiv_verify(g_state, "123456", &tries );
    if(res!=0)
    {
        printf("PIN Verification Failed, Error Code: %d\n", res);
    }

 const unsigned char test_key[] = {0x04,0xa9,0xee,0x8b,0x22,0xcb,0xa8,0xa0,0x9b,0x74,0xfd,0xe4,0x5a,0xe2,0xfe,0x6e,0xd6,0xf7,0xca,0xda,0xf1,0xf5,0x01,0xc5,0xf6,0x17,0x0d,0xf9,0x08,0x58,0x16,0xa8,0xd3,0x17,0xae,0xbc,0xe2,0x8d,0xfe,0x8c,0x58,0x97,0xab,0x63,0x74,0xf7,0x51,0xb8,0x09,0xec,0x42,0xa6,0xed,0x07,0x4b,0x54,0xc3,0x95,0xae,0x40,0x48,0x1c,0x42,0x08,0xdd};
 unsigned char secret[65];
 size_t len = 65;

 res = ykpiv_decipher_data(g_state, &test_key, 65, secret, &len , YKPIV_ALGO_ECCP256, 0x9a);

     if(res==0)
     {
         printf("ECDH Exchange Successful\n");
     }
     else
     {
         printf("ECDH Exchange Failed, Error Code: %d\n", res);
     }

   printf("ECDH Point: ");
    for (int v = 0; v < len; v++)
    {
        printf("%02x", secret[v]);
    }
   printf("\n");
}
