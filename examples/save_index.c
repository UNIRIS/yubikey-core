/* Stores 24 key indexes by converting each int index into 2 bytes raw format.
 Uses Key History Object to store the raw indexes and the subsequently fetches
 the raw saved indexes from it and recovers the indexes after conversion. */

//Compile gcc save_index.c -lykpiv -o save_index

#include <stdio.h>
#include <string.h>
#include <ykpiv/ykpiv.h>

#define MAX_KEYS 24

void main()
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

    /* Writing data to Key History Object requires MGM Key Authentication */
    const char *mgm_key = "010203040506070801020304050607080102030405060708";
    unsigned char key[24] = {};
    size_t key_len = sizeof(key);

    res = ykpiv_hex_decode(mgm_key, strlen(mgm_key), key, &key_len);

    /* Authenticate with the MGM KEY */
    res = ykpiv_authenticate(g_state, key);

    unsigned short index = 10000;
    unsigned char index_raw[3] = {0};

    index_raw[0]= 0;
        //big endian
        index_raw[1] = index >> 8;
        index_raw[2] = index;
  
    res = ykpiv_save_object(g_state, YKPIV_OBJ_KEY_HISTORY, index_raw, sizeof(index_raw));

    if (res == 0)
    {
        printf("Object saved\n");
    }
    else
    {
        printf("Error saving object %d\n", res);
    }

    unsigned char index_yk[3] = {0};
    size_t index_length;

    res = ykpiv_authenticate(g_state, key);
    res = ykpiv_fetch_object(g_state, YKPIV_OBJ_KEY_HISTORY, index_yk, &index_length);

    if (res == 0)
    {
        printf("Fetch Successful\nRaw Object: ");
    }
    else
    {
        printf("Fetch Unsuccessful %d\n", res);
    }

    for (int j = 0; j < index_length; j++)
    {
        printf("%d ", index_yk[j]);
    }

    unsigned short yk_index;

        yk_index = index_yk[1] << 8;
        yk_index += index_yk[2];

    printf("\nRecovered: %d\n", index_yk[0]);
    printf("\nOldest Key: %d\n", (index_yk[0]+1)%20);
    printf("\nPrevious Key: %d\n", (index_yk[0]-1+20)%20);
    printf("\nRecovered: %d\n", yk_index);

    unsigned short x = 9981;
    unsigned short offset = yk_index - x;
    
    
    printf("\nSlot: %d\n", (index_yk[0]-offset+20)%20);
}