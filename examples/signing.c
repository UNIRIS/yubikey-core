
/* SIGNING ACTION 

COMPILE : gcc signing.c -lcrypto -lykpiv -o signing
*/


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
#include<stddef.h>
#include<stdlib.h>
#include<openssl/bio.h>
#include<openssl/sha.h>



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

  

    

    /* generate key on slot 9c for signing*/

    uint8_t *point=NULL;
    size_t point_len;

    res=ykpiv_util_generate_key(g_state,
                0x9c,
                YKPIV_ALGO_ECCP256,
                YKPIV_PINPOLICY_ONCE,
                YKPIV_TOUCHPOLICY_DEFAULT,
                NULL,
                NULL,
                NULL,
                NULL,
                &point,
                &point_len);
    if(res==0)
    {
        printf("\nKey Generation in slot 9c successful\n");
    }
    else
    {
        printf("\nKey Generation in slot 9c NOT successful\n");
    }

    for(int i=0;i<point_len;i++)
    {
        printf("%02x", point[i]);

    }
    printf("\n");

    unsigned char attest[2048]={0};
    size_t attest_len=sizeof(attest);
    res=ykpiv_attest(g_state, 0x9c, attest, &attest_len);

    printf("\n\nCertificate\n");
    for(int i=0;i<attest_len;i++)
    {
        printf("%02x", attest[i]);
    }



    /* signing operation */

     unsigned char signature[512]={0};
     size_t n;
     unsigned char data[]={"lucy"};
     unsigned char hashed[20];
     SHA1(data, strlen(data), hashed);

     printf("\n Hashed Data \n");
     for (int i = 0; i < sizeof(hashed); i++)
     {
        printf("%02x", hashed[i] );
     }
     


    size_t signature_length=  sizeof(signature);
    size_t data_len= sizeof(hashed);
     n=sizeof(data);
    size_t padlen=256;
    


     /* Verify the Pin before Signing*/

       
    /* Pin Verification*/
    int tries=100;
    
    res=ykpiv_verify(g_state, "469901", &tries );

    if(res==0)
    {
        printf("Verification");
    }


    /* SIGN DATA */
   res=ykpiv_sign_data(g_state, hashed, data_len, signature, &signature_length, YKPIV_ALGO_ECCP256,0x9c );

    if(res==0)
    {
        printf("\nSigning Successful");
    }
    else{
        printf("\n%d\n", res);
        printf("\nSigning Unsuccesful");
    }
    printf("\n\n Signed Data \n\n");

    for(int i=0; i<signature_length; i++)
    {
        printf("%02x", signature[i]);
    }
    
    
   


    

}
