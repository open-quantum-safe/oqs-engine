#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#if defined(_WIN32)
#include <stdarg.h>
#endif

#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>
#include "oqse.h"
#include "oqse_err.h"

/**
* @brief Needs further clarification. Refer NIST web site,
*        section 4.A.5:Security Stregnth Categories.
*        for now base this on sig claimed nist levels
*
* @param s - OQS_SIG structure
*
* @return approx security bits base on nist claimed level or
*         0 on error
*
*/
int oqse_get_security_bits(OQS_SIG *s)
{
    if (!s)
    {
        return 0;
    }

    switch (s->claimed_nist_level)
    {
        case 1: return 128;
        case 2: return 256;
        case 3: return 192;
        case 4: return 384;
        case 5: return 256;
        default:
            OQSEerr(OQSE_F_OQSE_GET_SECURITY_BITS, OQSE_R_UNKNOWN_NIST_LEVEL);
            return 0;
    }
}


/**
* @brief clean and release a OQS_KEY context, including keys
*
* @param key    private ctx
*/
void oqse_pkey_ctx_free(OQS_KEY* key)
{
    int privkey_len = 0;
    if (key == NULL)
    {
        return;
    }
    if (key->s)
    {
        privkey_len = key->s->length_secret_key;
        OQS_SIG_free(key->s);
    }
    if (key->privkey)
    {
        OPENSSL_secure_clear_free(key->privkey, privkey_len);
    }
    if (key->pubkey)
    {
        OPENSSL_free(key->pubkey);
    }
    OPENSSL_free(key);
}

#if defined(_WIN32)
int asprintf(char **ret, const char *format, ...)
{
    va_list ap;
    *ret =  NULL;  /* Ensure value can be passed to free() */

    va_start(ap, format);
    int count = vsnprintf(NULL, 0, format, ap);
    va_end(ap);
    if (count >= 0)
    {
        char* buffer = malloc(count + 1);
        if (buffer == NULL)
            return -1;
        va_start(ap, format);
        count = vsnprintf(buffer, count + 1, format, ap);
        va_end(ap);
        if (count < 0)
        {
            free(buffer);
            return count;
        }
        *ret = buffer;
    }
    return count;
}
#endif

