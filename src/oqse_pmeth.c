#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/opensslv.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>
#include "oqse.h"
#include "oqse_err.h"
#include "oqse_utils.h"

/**
* @brief allocate and initialise an OQS key context
*
* @param p_oqs_key OQS_KEY ptr to allocate and return
* @param nid Numerical Identifier of OQS signing algorithm
* @param keytype Flag for private or public key
*
* @return 1 on success
*/
static int oqse_key_init(OQS_KEY **p_oqs_key, int nid, oqs_key_type_t keytype)
{
    OQS_KEY *oqs_key = NULL;
    int oqsid;

    oqs_key = OPENSSL_zalloc(sizeof(*oqs_key));
    if (oqs_key == NULL)
    {
        OQSEerr(OQSE_F_OQSE_KEY_INIT, OQSE_R_MALLOC_FAILED);
        goto err;
    }
    oqsid = oqse_nid2oqs(nid);
    oqs_key->s = OQS_SIG_new(OQS_SIG_alg_identifier(oqsid));
    if (oqs_key->s == NULL)
    {
        OQSEerr(OQSE_F_OQSE_KEY_INIT, OQSE_R_QSE_NEW_FAILED);
        goto err;
    }

    oqs_key->pubkey = OPENSSL_malloc(oqs_key->s->length_public_key);
    if (oqs_key->pubkey == NULL)
    {
        OQSEerr(OQSE_F_OQSE_KEY_INIT, OQSE_R_MALLOC_FAILED);
        goto err;
    }
    /* Optionally allocate the private key */
    if (keytype == KEY_TYPE_PRIVATE)
    {
        oqs_key->privkey = OPENSSL_secure_malloc(oqs_key->s->length_secret_key);
        if (oqs_key->privkey == NULL)
        {
            OQSEerr(OQSE_F_OQSE_KEY_INIT, OQSE_R_MALLOC_FAILED);
            goto err;
        }
    }
    oqs_key->security_bits = oqse_get_security_bits(oqs_key->s);
    *p_oqs_key = oqs_key;
    return 1;
 err:
    oqse_pkey_ctx_free(oqs_key);
    return 0;
}

/**
* @brief openssl ENGINE_SET_pkey_meth() function for pmeth lookup
*        pass **pmeth to NULL in order to retrieve *nids
*
* @param e ENGINE ptr
* @param pmeth EVP_PKEY method
* @param nids list of Numerical Identifiers
* @param nid Numerical Identifier for which to set pmeth
*
* @return if **pmeth==NULL, return number of signing algorithms
*         else 1 on success
*/
int oqse_pkey_pmeths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
    int i=0;

    (void)e;

    if(!pmeth)
    {
        // return list of NIDS
        *nids = oqse_pkey_asn1_meth_nids;
        return OQS_SIG_algs_length;
    }

    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        if ((oqse_global+i)->nid == nid)
        {
            *pmeth = (oqse_global+i)->pmeth;
            return 1;
        }
    }
    OQSEerr(OQSE_F_OQSE_PKEY_PMETHS, OQSE_R_NID_NOT_FOUND);
    *pmeth = NULL;
    return 0;
}

/**
* @brief openssl EVP_PKEY_meth_set_keygen() function;
*        the resultant key is set within the pkey, as OQS_KEY data
*
* @param ctx EVP_PKEY context
* @param pkey EVP_PKEY reference. 
*
* NB: app_data must has (*int) nid set before calling keygen.
*     this provides NID to OQS SIG translation on a
*     common interface
*
* @return 1 on success
*/
static int oqse_pmeth_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    OQS_KEY *oqs_key = NULL;
    int *pkey_nid = (int *) EVP_PKEY_CTX_get_app_data(ctx);

    if (!pkey_nid)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_KEYGEN, OQSE_R_NO_ALG_DATA);
       goto err;
    }
    if (!oqse_key_init(&oqs_key, *pkey_nid, 1))
    {
        OQSEerr(OQSE_F_OQSE_PMETH_KEYGEN, OQSE_R_BAD_INIT);
        goto err;
    }
    if (OQS_SIG_keypair(oqs_key->s, oqs_key->pubkey, oqs_key->privkey) != OQS_SUCCESS)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_KEYGEN, OQSE_R_FAILED_KEYGEN);
        goto err;
    }
    EVP_PKEY_assign(pkey, *pkey_nid, oqs_key); // caution ... i think this clears the engine
    return 1;

err:
    oqse_pkey_ctx_free(oqs_key);
    return 0;
}


/**
* @brief EVP_PKEY_SIGN function for OQS engine
*
* @param ctx - pkey context
* @param sig - signature
* @param siglen - length of signature
* @param tbs - data to be signed
* @param tbslen - length of data to be signed
*
* normally used to sign digests - does not hash cf digestsign functions
*
* @return 1 on success
*/
int oqse_pmeth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
    const char *nm = OBJ_nid2sn(EVP_PKEY_base_id(EVP_PKEY_CTX_get0_pkey(ctx)));

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey )
    {
        OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
        return 0;
    }

    // return size of siglen (at least from openssl point of view ie: signature part only)
    if (sig == NULL)
    {
        // for picnic, this overhead represents worst case max
        *siglen = oqs_key->s->length_signature;
        return 1;
    }
    if (*siglen < oqs_key->s->length_signature)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
        return 0;
    }

    // worst case is for picnic which includes 4 byte sig length, message and signature
    sig = realloc(sig, tbslen + *siglen + sizeof(uint32_t));
    if (!sig)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
        return 0;
    }
    if (strstr(nm,"picnic"))
    {
        // picnic encodes the sig length into the signaturee, so cannot verify abs sig length
        if (OQS_SIG_sign(oqs_key->s, sig, siglen, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS)
        {
            OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
            return 0;
        }
        if (*siglen > oqs_key->s->length_signature + tbslen + sizeof(uint32_t))
        {
            OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
            return 0;
        }
    }
    else
    {
        if (OQS_SIG_sign(oqs_key->s, sig, siglen, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS)
        {
            OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
            return 0;
        }
        if (*siglen != oqs_key->s->length_signature)
        {
            OQSEerr(OQSE_F_OQSE_PMETH_SIGN, OQSE_R_FATAL);
            return 0;
        }
    }
    return 1;
}

/**
* @brief EVP_PKEY_VERIFY function for OQS engine
*
* @param ctx - pkey context
* @param sig - signature
* @param siglen - length of signature
* @param tbs - data to be verified
* @param tbslen - length of data to be verified
*
* @return 1 on success
*/
static int oqse_pmeth_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
    int ret=0;

    if (!oqs_key)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_VERIFY, OQSE_R_FATAL);
        goto err;
    }

    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || sig == NULL || tbs == NULL)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_VERIFY, OQSE_R_FATAL);
        goto err;
    }
    if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig, siglen, oqs_key->pubkey) != OQS_SUCCESS)
    {
        //OQSEerr(OQSE_F_OQSE_PMETH_VERIFY, OQSE_R_FATAL);
        goto err;
    }
    ret = 1;
err:
    return ret;
}

#if 0
// TTD investigate why this is not valid OPENSSL_VERSION_NUMBER >= 0x10101000L
/**
* @brief 
*
* @param ctx
* @param sig
* @param siglen
* @param tbs
* @param tbslen
*
* @return 
*/
int oqse_pmeth_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen)
{
    EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));
    OQS_KEY * oqs_key = (OQS_KEY *) EVP_PKEY_get0(pkey);

    if (!oqs_key || !oqs_key->s || !oqs_key->privkey )
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTSIGN, OQSE_R_FATAL);
        return 0;
    }
    if (sig == NULL)
    {
        *siglen = oqs_key->s->length_signature;
        return 1;
    }
    if (*siglen < oqs_key->s->length_signature)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTSIGN, OQSE_R_FATAL);
        return 0;
    }
    sig = realloc(sig, tbslen + *siglen + sizeof(uint32_t));
    if (!sig)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTSIGN, OQSE_R_FATAL);
        return 0;
    }
    if (OQS_SIG_sign(oqs_key->s, sig, siglen, tbs, tbslen, oqs_key->privkey) != OQS_SUCCESS)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTSIGN, OQSE_R_FATAL);
        return 0;
    }
    return 1;
}

/**
* @brief 
*
* @param ctx
* @param sig
* @param siglen
* @param tbs
* @param tbslen
*
* @return 
*/
int oqse_pmeth_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen)
{
    EVP_PKEY * pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));
    OQS_KEY * oqs_key = (OQS_KEY *) EVP_PKEY_get0(pkey);

    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || sig == NULL || tbs == NULL)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTVERIFY, OQSE_R_FATAL);
        return 0;
    }

    if (OQS_SIG_verify(oqs_key->s, tbs, tbslen, sig, siglen, oqs_key->pubkey) != OQS_SUCCESS)
    {
        OQSEerr(OQSE_F_OQSE_PMETH_DIGESTVERIFY, OQSE_R_FATAL);
        return 0;
    }
    return 1;
}
#endif

static int oqse_pmeth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    (void) p1;
    (void) p2;
    (void) ctx;
    switch (type)
    {
    default:
        return 1;
        break;
    }
    return -2;
}

int oqse_register_pmeth(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
    *pmeth = EVP_PKEY_meth_new(id, flags);

    if (*pmeth == NULL)
        return 0;

    EVP_PKEY_meth_set_keygen(*pmeth, NULL, oqse_pmeth_keygen);
    EVP_PKEY_meth_set_sign(*pmeth, NULL, oqse_pmeth_sign);
    EVP_PKEY_meth_set_verify(*pmeth, NULL, oqse_pmeth_verify);

    // the following are not available in 1.1.0g, so we just implement item sign verify
    // version 1.1.1 provides these
#if 0
    EVP_PKEY_meth_set_digestsign(*pmeth, oqse_pmeth_digestsign);
    EVP_PKEY_meth_set_digestverify(*pmeth, oqse_pmeth_digestverify);
#endif
    EVP_PKEY_meth_set_ctrl(*pmeth, oqse_pmeth_ctrl, NULL);
    return 1;
}
