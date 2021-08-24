/* Stores 24 key indexes by converting each int index into 2 bytes raw format.
 Uses Key History Object to store the raw indexes and the subsequently fetches
 the raw saved indexes from it and recovers the indexes after conversion. */

//Compile gcc object.c -lykpiv -o object

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

    unsigned short indexes[MAX_KEYS] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
    unsigned char indexes_raw[2 * MAX_KEYS] = {0};

    for (int v = 0; v < MAX_KEYS; v++)
    {
        //big endian
        indexes_raw[2 * v] = indexes[v] >> 8;
        indexes_raw[2 * v + 1] = indexes[v];
    }

    res = ykpiv_save_object(g_state, YKPIV_OBJ_KEY_HISTORY, indexes_raw, sizeof(indexes_raw));

    if (res == 0)
    {
        printf("Object saved\n");
    }
    else
    {
        printf("Error saving object %d\n", res);
    }

    unsigned char indexes_yk[2 * MAX_KEYS] = {0};
    uint64_t indexes_length;

    res = ykpiv_authenticate(g_state, key);
    res = ykpiv_fetch_object(g_state, YKPIV_OBJ_KEY_HISTORY, indexes_yk, &indexes_length);

    if (res == 0)
    {
        printf("Fetch Successful\nRaw Object: ");
    }
    else
    {
        printf("Fetch Unsuccessful %d\n", res);
    }

    for (int j = 0; j < indexes_length; j++)
    {
        printf("%02x", indexes_yk[j]);
    }

    unsigned short yk_indexes[MAX_KEYS];
    for (int d = 0; d < indexes_length; d += 2)
    {
        yk_indexes[d / 2] = indexes_yk[d] << 8;
        yk_indexes[d / 2] += indexes_yk[d + 1];
    }

    printf("\nRecovered: ");
    for (int k = 0; k < MAX_KEYS; k++)
    {
        printf("%d ", yk_indexes[k]);
    }
    printf("\n");
}