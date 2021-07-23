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


/* openssl req -new -x509 -days 3650 -config openssl.cnf -extensions v3_ca -key ec-cakey.pem  ;
openssl req -new -x509 -days 3650  -extensions v3_ca -key ec-cakey.pem */


   static const char *certificate_pem =
  "-----BEGIN CERTIFICATE-----\n"
"MIICYTCCAgegAwIBAgIURg+gidZMO5UcMA2VBDH+65JnaC8wCgYIKoZIzj0EAwIw\n"
"gYUxCzAJBgNVBAYTAklOMRQwEgYDVQQIDAtNYWhhcmFzaHRyYTENMAsGA1UEBwwE\n"
"cHVuZTEPMA0GA1UECgwGdW5pcmlzMQwwCgYDVQQLDAN4eXoxCzAJBgNVBAMMAmNj\n"
"MSUwIwYJKoZIhvcNAQkBFhZsdWN5c2hhcm1hOTVAZ21haWwuY29tMB4XDTIxMDcy\n"
"MzA2NTY1MloXDTMxMDcyMTA2NTY1MlowgYUxCzAJBgNVBAYTAklOMRQwEgYDVQQI\n"
"DAtNYWhhcmFzaHRyYTENMAsGA1UEBwwEcHVuZTEPMA0GA1UECgwGdW5pcmlzMQww"
"CgYDVQQLDAN4eXoxCzAJBgNVBAMMAmNjMSUwIwYJKoZIhvcNAQkBFhZsdWN5c2hh\n"
"cm1hOTVAZ21haWwuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE41AdBNgZ\n"
"ffJRtLut3CS80ULihRiddqZYExCZtKu9FghM6IWrXVt0XqgablxRKF6ua8c0C6Yv\n"
"9LZOQRjVvn9tkaNTMFEwHQYDVR0OBBYEFC41J7HBMIZyE50YRMnSuoXPuo17MB8G\n"
"A1UdIwQYMBaAFC41J7HBMIZyE50YRMnSuoXPuo17MA8GA1UdEwEB/wQFMAMBAf8w\n"
"CgYIKoZIzj0EAwIDSAAwRQIgBFSHIY7tMTRYmaQTHKPbOekccUvB+7wLOjutXgGt\n"
"dD4CIQCdOmlXw/PDu9opzFVFm2QWrtILl6mYRRjw2FXwGxatOg==\n"
"-----END CERTIFICATE-----\n";


    BIO *bio=NULL;
    
    X509 *x509=NULL;
    EVP_PKEY *pubkey=NULL;
    EC_KEY *tmpkey=NULL;

    int key=0;
    unsigned char algorithm;
    pubkey=X509_get_pubkey(x509);

    

    bio=BIO_new_mem_buf(certificate_pem, strlen(certificate_pem));
    x509=PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    pubkey=X509_get_pubkey(x509);

    
    
    unsigned char secret[48]={0};
    unsigned char secret2[48]={0};
    unsigned char public_key[97]={0};
    unsigned char *ptr=public_key;
    size_t len=sizeof(secret);
    EC_KEY *ec=EVP_PKEY_get1_EC_KEY(pubkey);
    int nid;
    size_t key_len=32;

    tmpkey=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if(EC_KEY_generate_key(tmpkey)!=1)
    {
        fprintf(stderr, "Failed to generate EC key");

    }
     if(ECDH_compute_key(secret, len, EC_KEY_get0_public_key(ec), tmpkey, NULL)== -1)
     {
         fprintf(stderr, "Failed to compute ECDH key\n");
     }
     else{
         printf("Successfullly Generated ECDH key");
     }


    /* Generate key on YKPIV slot 9c before Exchange */

    /* Authenticate MGM Key */
    /* Generating the key pair  require authentication, which is done by providing the management key. 
    const char *mgm_key="7a5547f4b70dfe578c6681e98b07cc399782b1c84112c733";
    unsigned char mkey[24]={};
    size_t mkey_len=sizeof(mkey);
    
    res=ykpiv_hex_decode(mgm_key, strlen(mgm_key), mkey, &mkey_len);
     
    /* Authenticate the MGM KEY */
   /* res=ykpiv_authenticate(g_state, mkey); */

      /* ECC Public Point **/

    /*  
    uint8_t *point=NULL;
    size_t point_len; */

    /** Key Generation */

    /*res=ykpiv_util_generate_key(g_state,
                0x9a,
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
        printf("\nKey Generated on slot 9c ");
    } 
*/

    /* PIN verification before ECDH  Exchange*/

    int tries=100;
    
    res=ykpiv_verify(g_state, "469901", &tries );

    if(res==0)
    {
        printf("\nVerification");
    }


    
     res=ykpiv_decipher_data(g_state, public_key, (key_len*2)+1, secret2, &len, YKPIV_ALGO_ECCP256, 0x9a);

     if(res==0)
     {
         printf("\nECDH exchange successful\n");
     }
     else
     {
         printf("\nECDH exchange failed\n %d", res);
     }



}


