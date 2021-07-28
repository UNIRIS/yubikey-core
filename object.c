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

    int obj_id=1;
    unsigned char test_key[] = {0x04,0xa9,0xee,0x8b,0x22,0xcb,0xa8,0xa0,0x9b,0x74,0xfd,0xe4,0x5a,0xe2,0xfe,0x6e,0xd6,0xf7,0xca,0xda,0xf1,0xf5,0x01,0xc5,0xf6,0x17,0x0d,0xf9,0x08,0x58,0x16,0xa8,0xd3,0x17,0xae,0xbc,0xe2,0x8d,0xfe,0x8c,0x58,0x97,0xab,0x63,0x74,0xf7,0x51,0xb8,0x09,0xec,0x42,0xa6,0xed,0x07,0x4b,0x54,0xc3,0x95,0xae,0x40,0x48,0x1c,0x42,0x08,0xdd};
    size_t len=sizeof(test_key);

    res= ykpiv_save_object(g_state, obj_id, test_key, len);

    if(res==0)
    {
        printf("Object saved");

    }
    else{
        printf("Error saving object %d", res);
    }
}