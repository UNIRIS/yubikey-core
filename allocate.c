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


struct t_alloc_data{
    uint32_t count;

}g_alloc_data;


static void* _test_alloc(void *data, size_t cb)
{
    ((struct t_alloc_data*)data)->count++;
    return calloc(cb,1);
}

ykpiv_allocator test_allocator_cbs={
    .pfn_alloc=_test_alloc,
    .alloc_data=&g_alloc_data
};


uint8_t *alloc_auth_cert()
{
    ykpiv_rc res;
    uint8_t *read_cert=NULL;
    size_t read_cert_len=0;
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


    res=ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert,&read_cert_len);

    return read_cert;
    
}


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



   const ykpiv_allocator allocator;
   uint8_t *cert1, *cert2;

   res=ykpiv_done(g_state);
   g_state=NULL;

   res=ykpiv_init_with_allocator(&g_state, false, &test_allocator_cbs );

   res=ykpiv_connect(g_state, NULL);

   /* Generating the key pair  require authentication, which is done by providing the management key. */
    const char *mgm_key="7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char key[24]={};
    size_t key_len=sizeof(key);
    
    res=ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
     
    /* Authenticate the MGM KEY */
    res=ykpiv_authenticate(g_state, key);



    cert1=alloc_auth_cert();
    cert2=alloc_auth_cert();

    ykpiv_util_free(g_state, cert2);
    ykpiv_util_free(g_state, cert1);
    res=ykpiv_disconnect(g_state);
    res=ykpiv_done(g_state);

    g_state=NULL;


}