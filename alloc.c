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

ykpiv_state *g_state;
struct t_alloc_data{
    uint32_t count;

}g_alloc_data;


static void* _test_alloc(void *data, size_t cb)
{
    ((struct t_alloc_data*)data)->count++;
    return calloc(cb,1);
}

static void * test_realloc(void *data, void *p, size_t cb)
{
    return realloc(p, cb);
}

static void _test_free(void *data, void *p)
{
    ((struct t_alloc_data*)data)->count--;
    free(p);
}

/* allocater structure */

ykpiv_allocator test_allocator_cbs={
    .pfn_alloc=_test_alloc,
    .pfn_realloc=test_realloc,
    .pfn_free=_test_free,
    .alloc_data=&g_alloc_data
};


uint8_t *alloc_auth_cert()
{
    ykpiv_rc res;
    uint8_t *read_cert=NULL;
    size_t read_cert_len=0;


    res=ykpiv_util_read_cert(g_state, YKPIV_KEY_AUTHENTICATION, &read_cert,&read_cert_len);
    

    return read_cert;
    
}


void main()
{
   ykpiv_rc res;

   const ykpiv_allocator allocator;
   uint8_t *cert1, *cert2;

   
   res=ykpiv_init_with_allocator(&g_state, false, &test_allocator_cbs );

   if(res==0)
   {
       printf("\nAllocation Successful");
   }
   else
   {
       printf("\n %d Could not allocate", res);
   }

   res=ykpiv_connect(g_state, NULL);
   if(res!=0)
   {
       printf("\n Connection Unsuccessful");
   }

   /* Authenticate */
    const char *mgm_key="7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char key[24]={};
    size_t key_len=sizeof(key);
    
    res=ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);
     
    /* Authenticate the MGM KEY */
    res=ykpiv_authenticate(g_state, key);


    /*allocate the data*/
    cert1=alloc_auth_cert();
    cert2=alloc_auth_cert();

    ykpiv_util_free(g_state, cert2);
    ykpiv_util_free(g_state, cert1);
    res=ykpiv_disconnect(g_state);
    res=ykpiv_done(g_state);

    g_state=NULL;


}
