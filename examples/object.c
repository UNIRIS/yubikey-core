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

    
    unsigned char index1[] =
{
	0x70,0x59,0x60,0x14,0x57,0x12,0x47,0x61,
	
};
    size_t len=sizeof(index1);

    res= ykpiv_save_object(g_state, YKPIV_OBJ_IRIS, index1, len);

    if(res==0)
    {
        printf("Object saved");

    }
    else{
        printf("Error saving object %d", res);
    }



    






}