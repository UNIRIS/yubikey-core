// Compile: gcc support.c -o support stdio_helpers.c uniris-yubikey.c -lykpiv -lcrypto
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include "stdio_helpers.h"
#include "uniris-yubikey.h"

void write_error(unsigned char *buf, char *error_message, int error_message_len);

enum
{
    INITIALIZE_YK = 1,
    GET_ARCHETHIC_INDEX = 2,
    INCREMENT_INDEX = 3,
    GET_ROOT_KEY = 4,
    GET_CURRENT_KEY = 5,
    GET_NEXT_KEY = 6,
    GET_PAST_KEY = 7,
    GET_ROOT_CERTIFICATE = 8,
    GET_CURRENT_CERTIFICATE = 9,
    GET_NEXT_CERTIFICATE = 10,
    GET_PAST_CERTIFICATE = 11,
    SIGN_CURRENT_KEY = 12,
    SIGN_PAST_KEY = 13,
    ECDH_CURRENT_KEY = 14,
    ECDH_PAST_KEY = 15,
    CHECK_YK_CONNECTION = 16
};

void initialize_yk(unsigned char *buf, int pos, int len)
{
    initializeYK();

    int response_len = 5;
    unsigned char response[response_len];

    //Encoding of the request id
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success(1) or failure(0)
    response[4] = checkYK();
    write_response(response, response_len);
}

void check_yk_connection(unsigned char *buf, int pos, int len)
{
    int response_len = 5;
    unsigned char response[response_len];

    //Encoding of the request id
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of status (1 if connected, else 0)
    response[4] = checkYK();
    write_response(response, response_len);
}


void get_archethic_index(unsigned char *buf, int pos, int len)
{
    INT keyIndex = 0;
    keyIndex = getArchEthicIndex();
    int response_len = 5 + 2;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }
    // Encoding of success
    response[4] = 1;
    response[5] = keyIndex >> 8;
    response[6] = keyIndex;
    write_response(response, response_len);
}

void increment_index(unsigned char *buf, int pos, int len)
{
    bool increment = incrementIndex();
    int response_len = 5 + 1;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }
    // Encoding of success
    response[4] = 1;
    response[5] = increment;
    write_response(response, response_len);
}

void get_root_key(unsigned char *buf, int pos, int len)
{
    BYTE *rawRSAkey;
    INT publicKeySize = 0;
    rawRSAkey = getRootKey(&publicKeySize);
    int response_len = 5 + publicKeySize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < publicKeySize; i++)
    {
        response[5 + i] = rawRSAkey[i];
    }
    write_response(response, response_len);
}

void get_current_key(unsigned char *buf, int pos, int len)
{
    BYTE *rawECCkey;
    INT publicKeySize = 0;
    rawECCkey = getCurrentKey(&publicKeySize);
    int response_len = 5 + publicKeySize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < publicKeySize; i++)
    {
        response[5 + i] = rawECCkey[i];
    }
    write_response(response, response_len);
}

void get_next_key(unsigned char *buf, int pos, int len)
{
    BYTE *rawECCkey;
    INT publicKeySize = 0;
    rawECCkey = getNextKey(&publicKeySize);
    int response_len = 5 + publicKeySize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < publicKeySize; i++)
    {
        response[5 + i] = rawECCkey[i];
    }
    write_response(response, response_len);
}

void get_past_key(unsigned char *buf, int pos, int len)
{
    if (len < pos + 2)
    {
        write_error(buf, "missing index", 13);
    }
    else
    {
        BYTE index[2];
        for (int i = 0; i < 2; i++)
        {
            index[i] = buf[pos + i];
        }

        INT index_int = index[1] | index[0] << 8;

        BYTE *rawECCkey;
        INT publicKeySize = 0;
        rawECCkey = getPastKey(index_int, &publicKeySize);
        int response_len = 5 + publicKeySize;
        unsigned char response[response_len];
        for (int i = 0; i < 4; i++)
        {
            response[i] = buf[i];
        }

        // Encoding of success
        response[4] = 1;

        for (int i = 0; i < publicKeySize; i++)
        {
            response[5 + i] = rawECCkey[i];
        }

        write_response(response, response_len);
    }
}

void get_root_certificate(unsigned char *buf, int pos, int len)
{
    BYTE *asnRSAcertificate;
    INT certificateSize = 0;
    asnRSAcertificate = getRootCertificate(&certificateSize);
    int response_len = 5 + certificateSize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < certificateSize; i++)
    {
        response[5 + i] = asnRSAcertificate[i];
    }
    write_response(response, response_len);
}

void get_current_certificate(unsigned char *buf, int pos, int len)
{
    BYTE *asnRSAcertificate;
    INT certificateSize = 0;
    asnRSAcertificate = getCurrentCertificate(&certificateSize);
    int response_len = 5 + certificateSize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < certificateSize; i++)
    {
        response[5 + i] = asnRSAcertificate[i];
    }
    write_response(response, response_len);
}

void get_next_certificate(unsigned char *buf, int pos, int len)
{
    BYTE *asnRSAcertificate;
    INT certificateSize = 0;
    asnRSAcertificate = getNextCertificate(&certificateSize);
    int response_len = 5 + certificateSize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < certificateSize; i++)
    {
        response[5 + i] = asnRSAcertificate[i];
    }
    write_response(response, response_len);
}

void get_past_certificate(unsigned char *buf, int pos, int len)
{
    if (len < pos + 2)
    {
        write_error(buf, "missing index", 13);
    }
    else
    {
        BYTE index[2];
        for (int i = 0; i < 2; i++)
        {
            index[i] = buf[pos + i];
        }

        INT index_int = index[1] | index[0] << 8;

        BYTE *asnRSAcertificate;
        INT certificateSize = 0;
        asnRSAcertificate = getPastCertificate(index_int, &certificateSize);
        int response_len = 5 + certificateSize;
        unsigned char response[response_len];
        for (int i = 0; i < 4; i++)
        {
            response[i] = buf[i];
        }

        // Encoding of success
        response[4] = 1;

        for (int i = 0; i < certificateSize; i++)
        {
            response[5 + i] = asnRSAcertificate[i];
        }

        write_response(response, response_len);
    }
}

void sign_current_key(unsigned char *buf, int pos, int len)
{
    BYTE hash256[32];

    for (int i = 0; i < 32; i++)
    {
        hash256[i] = buf[pos + i];
    }

    BYTE *eccSign;
    INT signLen = 0;

    eccSign = signCurrentKey(hash256, &signLen);

    int response_len = 5 + signLen;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < signLen; i++)
    {
        response[5 + i] = eccSign[i];
    }

    write_response(response, response_len);
}

void sign_past_key(unsigned char *buf, int pos, int len)
{
    BYTE hash256[32];

    if (len < pos + 2)
    {
        write_error(buf, "missing index", 13);
    }
    else
    {
        BYTE index[2];
        for (int i = 0; i < 2; i++)
        {
            index[i] = buf[pos + i];
        }

        pos += 2;

        for (int i = 0; i < 32; i++)
        {
            hash256[i] = buf[pos + i];
        }

        INT index_int = index[1] | index[0] << 8;

        BYTE *eccSign;
        INT signLen = 0;

        eccSign = signPastKey(index_int, hash256, &signLen);

        int response_len = 5 + signLen;
        unsigned char response[response_len];
        for (int i = 0; i < 4; i++)
        {
            response[i] = buf[i];
        }

        // Encoding of success
        response[4] = 1;

        for (int i = 0; i < signLen; i++)
        {
            response[5 + i] = eccSign[i];
        }

        write_response(response, response_len);
    }
}

void ecdh_current_key(unsigned char *buf, int pos, int len)
{
    BYTE ephemeral_key[65];

    for (int i = 0; i < 65; i++)
    {
        ephemeral_key[i] = buf[pos + i];
    }

    BYTE *ecdhPoint;
    INT eccPointSize;
    ecdhPoint = ecdhCurrentKey(ephemeral_key, &eccPointSize);

    int response_len = 5 + eccPointSize;
    unsigned char response[response_len];
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Encoding of success
    response[4] = 1;

    for (int i = 0; i < eccPointSize; i++)
    {
        response[5 + i] = ecdhPoint[i];
    }

    write_response(response, response_len);
}

void ecdh_past_key(unsigned char *buf, int pos, int len)
{
    BYTE ephemeral_key[65];

    if (len < pos + 2)
    {
        write_error(buf, "missing index", 13);
    }
    else
    {
        BYTE index[2];
        for (int i = 0; i < 2; i++)
        {
            index[i] = buf[pos + i];
        }

        pos += 2;

        for (int i = 0; i < 65; i++)
        {
            ephemeral_key[i] = buf[pos + i];
        }

        INT index_int = index[1] | index[0] << 8;

        BYTE *ecdhPoint;
        INT eccPointSize;
        ecdhPoint = ecdhPastKey(index_int, ephemeral_key, &eccPointSize);

        int response_len = 5 + eccPointSize;
        unsigned char response[response_len];
        for (int i = 0; i < 4; i++)
        {
            response[i] = buf[i];
        }

        // Encoding of success
        response[4] = 1;

        for (int i = 0; i < eccPointSize; i++)
        {
            response[5 + i] = ecdhPoint[i];
        }

        write_response(response, response_len);
    }
}

int main()
{
    int len = get_length();

    while (len > 0)
    {

        unsigned char *buf = (unsigned char *)malloc(len);
        int read_bytes = read_message(buf, len);

        if (read_bytes != len)
        {
            free(buf);
            err(EXIT_FAILURE, "missing message");
        }

        if (len < 4)
        {
            free(buf);
            err(EXIT_FAILURE, "missing request id");
        }
        int pos = 4; //After the 32 bytes of the request id

        if (len < 5)
        {
            free(buf);
            err(EXIT_FAILURE, "missing function id");
        }

        unsigned char function_id = buf[pos];
        pos++;

        switch (function_id)
        {
        case INITIALIZE_YK:
            initialize_yk(buf, pos, len);
            break;
        case CHECK_YK_CONNECTION:
            check_yk_connection(buf, pos, len);
            break;
        case GET_ARCHETHIC_INDEX:
            get_archethic_index(buf, pos, len);
            break;
        case INCREMENT_INDEX:
            increment_index(buf, pos, len);
            break;
        case GET_ROOT_KEY:
            get_root_key(buf, pos, len);
            break;
        case GET_CURRENT_KEY:
            get_current_key(buf, pos, len);
            break;
        case GET_NEXT_KEY:
            get_next_key(buf, pos, len);
            break;
        case GET_PAST_KEY:
            get_past_key(buf, pos, len);
            break;
        case GET_ROOT_CERTIFICATE:
            get_root_certificate(buf, pos, len);
            break;
        case GET_CURRENT_CERTIFICATE:
            get_current_certificate(buf, pos, len);
            break;
        case GET_NEXT_CERTIFICATE:
            get_next_certificate(buf, pos, len);
            break;
        case GET_PAST_CERTIFICATE:
            get_past_certificate(buf, pos, len);
            break;
        case SIGN_CURRENT_KEY:
            sign_current_key(buf, pos, len);
            break;
        case SIGN_PAST_KEY:
            sign_past_key(buf, pos, len);
            break;
        case ECDH_CURRENT_KEY:
            ecdh_current_key(buf, pos, len);
            break;
        case ECDH_PAST_KEY:
            ecdh_past_key(buf, pos, len);
            break;
        }

        free(buf);
        len = get_length();
    }
}

void write_error(unsigned char *buf, char *error_message, int error_message_len)
{
    int response_size = 5 + error_message_len;
    unsigned char response[response_size];

    //Encode the request id
    for (int i = 0; i < 4; i++)
    {
        response[i] = buf[i];
    }

    // Error response type
    response[4] = 0;

    //Encode the error message
    for (int i = 0; i < error_message_len; i++)
    {
        response[5 + i] = error_message[i];
    }
    write_response(response, response_size);
}