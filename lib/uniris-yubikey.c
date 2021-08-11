#include <stdio.h>
#include <ykpiv/ykpiv.h>

ykpiv_rc rc;
static ykpiv_state *g_state;

void initializeYK()
{
    /* Intialize */
    rc = ykpiv_init(&g_state, true);
    if (rc != 0)
    {
        printf("Initialization Failed, Error Code: %d\n", rc);
    }

    /* Connect */
    rc = ykpiv_connect(g_state, NULL);
    if (rc != 0)
    {
        printf("Connection Failed, Error Code: %d\n", rc);
    }
}