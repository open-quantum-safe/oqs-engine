#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>
#include "oqse.h"
#include "oqse_err.h"
#include "oqse_utils.h"

/**
* @brief openssl ENGINE_set_pkey_asn1_meths() function for ASN1 method lookup
*
* @param e      openssl ENGINE ptr
* @param ameth  asn1 method to return
* @param nids   list of nids registered
* @param nid    NID to return ASN1 method
*
* @return  0 on error
*/
int oqse_pkey_ameths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
    int i=0;

    (void)e;

    if(!ameth)
    {
        // return list of NIDS
        *nids = oqse_pkey_asn1_meth_nids;
        return OQS_SIG_algs_length;
    }

    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        if ((oqse_global+i)->nid == nid)
        {
            *ameth = (oqse_global+i)->ameth;
            return 1;
        }
    }
    OQSEerr(OQSE_F_OQSE_PKEY_AMETHS, OQSE_R_NID_NOT_FOUND);
    *ameth = NULL;
    return 0;
}

/**
* @brief free EVP_PKEY
*
* @param pkey   openssl PKEY
*/
static void oqse_free(EVP_PKEY *pkey)
{
    oqse_pkey_ctx_free((OQS_KEY*) EVP_PKEY_get0(pkey));
}

/**
* @brief Initialize a new OQS_KEY, based on the OPENSSL NID
*
* @param p_oqs_key  private OQS data
* @param nid        openssl NID
* @param keytype    flag to allocate private key
*
* @return  0 on error
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
* @brief lookup OQS public key length
*
* @param pkey   openssl EVP_PKEY
*
* @return public key length in bits
*/
static int oqse_asn1_bits(const EVP_PKEY *pkey)
{
    OQS_KEY * oqs_key = EVP_PKEY_get0(pkey);
    if (oqs_key)
        return (oqs_key->s->length_public_key);
    else
    {
        OQSEerr(OQSE_F_OQSE_ASN1_BITS, OQSE_R_NO_DATA);
        return 0;
    }
}

/**
* @brief lookup OQS security bits
*
* @param pkey openssl EVP_PKEY
*
* @return OQS key security bits
*/
static int oqse_asn1_security_bits(const EVP_PKEY *pkey)
{
    OQS_KEY * oqs_key = EVP_PKEY_get0(pkey);
    if (oqs_key)
        return (oqs_key->security_bits);
    else
    {
        OQSEerr(OQSE_F_OQSE_ASN1_SECURITY_BITS, OQSE_R_NO_DATA);
        return 0;
    }
}


/**
* @brief output EVP_PKEY as ASN1 representation to given BIO
*
* @param bp OpenSSL BIO
* @param pkey EVP_PKEY to print
* @param indent formatting control
* @param ctx ASN1 context
* @param keytype flag as public or private key
*
* @return 0 on error
*/
static int oqse_key_print(BIO *bp,
                         const EVP_PKEY *pkey,
                         int indent,
                         ASN1_PCTX *ctx,
                         oqs_key_type_t keytype)
{
    const OQS_KEY *oqskey = EVP_PKEY_get0(pkey);
    const char *nm = OBJ_nid2ln(EVP_PKEY_base_id(pkey));

    (void)ctx;

    if (keytype == KEY_TYPE_PRIVATE)
    {
        if (oqskey == NULL || oqskey->privkey == NULL)
        {
            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nm) <= 0)
            return 0;
        if (BIO_printf(bp, "%*spriv:\n", indent, "") <= 0)
            return 0;
        if (ASN1_buf_print(bp, oqskey->privkey, oqskey->s->length_secret_key, indent + 4) == 0)
            return 0;
    }
    else
    {
        if (oqskey == NULL)
        {
            if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
                return 0;
            return 1;
        }
        if (BIO_printf(bp, "%*s%s Public-Key:\n", indent, "", nm) <= 0)
            return 0;
    }
    if (BIO_printf(bp, "%*spub:\n", indent, "") <= 0)
        return 0;

    if (ASN1_buf_print(bp, oqskey->pubkey, oqskey->s->length_public_key, indent + 4) == 0)
        return 0;
    return 1;
}

/*
* @brief output EVP_PKEY private key as ASN1 representation to given BIO
*
* @param bp OpenSSL BIO
* @param pkey EVP_PKEY to print
* @param indent formatting control
* @param ctx ASN1 context
*
* @return 0 on error
*/
static int oqse_asn1_priv_print(BIO *bp,
                               const EVP_PKEY *pkey,
                               int indent,
                               ASN1_PCTX *ctx)
{
    return oqse_key_print(bp, pkey, indent, ctx, KEY_TYPE_PRIVATE);
}

/**
* @brief output EVP_PKEY public key as ASN1 representation to given BIO
*
* @param bp OpenSSL BIO
* @param pkey EVP_PKEY to print
* @param indent formatting control
* @param ctx ASN1 context
*
* @return 0 on error
*/
static int oqse_asn1_pub_print(BIO *bp,
                              const EVP_PKEY *pkey,
                              int indent,
                              ASN1_PCTX *ctx)
{
    return oqse_key_print(bp, pkey, indent, ctx, KEY_TYPE_PUBLIC);
}

/**
* @brief EVP_PKEY compare routine
*
* @param a
* @param b
*
* @return result of memcmp
*/
static int oqse_asn1_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
    const OQS_KEY *akey = (OQS_KEY*) EVP_PKEY_get0(a); //->pkey.ptr;
    const OQS_KEY *bkey = (OQS_KEY*) EVP_PKEY_get0(b); //b->pkey.ptr;
    if (akey == NULL || bkey == NULL)
        return -2;

    // TTD should probably check NIDS here as well.

    return CRYPTO_memcmp(akey->pubkey, bkey->pubkey, akey->s->length_public_key) == 0;
}

#if 0
static int oqse_size(const EVP_PKEY *pkey)
{
    const OQS_KEY *oqskey = (OQS_KEY*) EVP_PKEY_get0(pkey); //pkey->pkey.ptr;
    if (oqskey == NULL || oqskey->s == NULL)
    {
        OQSEerr(OQSE_F_OQSE_SIZE, OQSE_R_FATAL);
        return 0;
    }
    return oqskey->s->length_signature;
}
#endif

/**
* @brief 
*
* @param a
* @param b
*
* @return 
*/
static int oqse_asn1_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b)
{
    (void)a;
    (void)b;
    // TTD - check this
    return 1;
}

/**
* @brief 
*
* @param p8
* @param pkey
*
* @return 
*/
static int oqse_asn1_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqskey = (OQS_KEY*) EVP_PKEY_get0(pkey);
    ASN1_OCTET_STRING oct;
    unsigned char *buf = NULL, *penc = NULL;
    int buflen = oqskey->s->length_secret_key + oqskey->s->length_public_key, penclen;

    buf = OPENSSL_secure_malloc(buflen);
    if (buf == NULL)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_ENCODE, OQSE_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(buf, oqskey->privkey, oqskey->s->length_secret_key);
    memcpy(buf + oqskey->s->length_secret_key, oqskey->pubkey, oqskey->s->length_public_key);
    oct.data = buf;
    oct.length = buflen;
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0)
    {
        OPENSSL_secure_clear_free(buf, buflen);
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_ENCODE, OQSE_R_MALLOC_FAILURE);
        return 0;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(EVP_PKEY_base_id(pkey)), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_secure_clear_free(buf, buflen);
        OPENSSL_clear_free(penc, penclen);
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_ENCODE, OQSE_R_MALLOC_FAILURE);
        return 0;
    }

    OPENSSL_secure_clear_free(buf, buflen);
    return 1;
}

/**
* @brief 
*
* @param pkey
* @param p8
*
* @return 
*/
static int oqse_asn1_priv_decode(EVP_PKEY *pkey, const PKCS8_PRIV_KEY_INFO *p8)
{
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8))
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_DECODE, OQSE_R_NO_KEY);
        return 0;
    }

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL)
    {
        p = NULL;
        plen = 0;
    }
    else
    {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }

    /* oct contains first the private key, then the public key */
    if (palg != NULL)
    {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF)
        {
            OQSEerr(OQSE_F_OQSE_ASN1_PRIV_DECODE, OQSE_R_NO_ALGOR);
            return 0;
        }
    }

    if (!oqse_key_init(&oqs_key, EVP_PKEY_base_id(pkey), 1))
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_DECODE, OQSE_R_FATAL);
        return 0;
    }
    if ((unsigned int) plen != oqs_key->s->length_secret_key + oqs_key->s->length_public_key)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PRIV_DECODE, OQSE_R_FATAL);
        oqse_pkey_ctx_free(oqs_key);
        return 0;
    }
    memcpy(oqs_key->privkey, p, oqs_key->s->length_secret_key);
    memcpy(oqs_key->pubkey, p + oqs_key->s->length_secret_key, oqs_key->s->length_public_key);
    EVP_PKEY_assign(pkey, EVP_PKEY_base_id(pkey), oqs_key);

    ASN1_OCTET_STRING_free(oct);
    return 1;
}

/**
* @brief 
*
* @param pk
* @param pkey
*
* @return 
*/
static int oqse_asn1_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
{
    const OQS_KEY *oqs_key = (OQS_KEY*) EVP_PKEY_get0(pkey);
    unsigned char *penc;
    if (!oqs_key || !oqs_key->s || !oqs_key->pubkey )
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_ENCODE, OQSE_R_FATAL);
        return 0;
    }

    penc = OPENSSL_memdup(oqs_key->pubkey, oqs_key->s->length_public_key);
    if (penc == NULL)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_ENCODE, OQSE_R_MALLOC_FAIL);
        return 0;
    }

    if (!X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_base_id(pkey)),
                                V_ASN1_UNDEF, NULL, penc, oqs_key->s->length_public_key))
    {
        OPENSSL_free(penc);
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_ENCODE, OQSE_R_FATAL);
        return 0;
    }
    return 1;
}

/**
* @brief 
*
* @param pkey
* @param pubkey
*
* @return 
*/
static int oqse_asn1_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    const unsigned char *p;
    int pklen;
    X509_ALGOR *palg;
    OQS_KEY *oqs_key = NULL;
    int id = EVP_PKEY_base_id(pkey);

    if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, &palg, pubkey)) {
        return 0;
    }

    if (p == NULL)
    {
        /* pklen is checked below, after we instantiate the oqs_key to learn the expected len */
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_DECODE, OQSE_R_FATAL);
        return 0;
    }

    if (palg != NULL)
    {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF)
        {
            OQSEerr(OQSE_F_OQSE_ASN1_PUB_DECODE, OQSE_R_FATAL);
            return 0;
        }
    }

    if (!oqse_key_init(&oqs_key, id, 0))
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_DECODE, OQSE_R_FATAL);
        return 0;
    }

    if ((unsigned int) pklen != oqs_key->s->length_public_key)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_PUB_DECODE, OQSE_R_FATAL);
        oqse_pkey_ctx_free(oqs_key);
        return 0;
    }
    memcpy(oqs_key->pubkey, p, pklen);
    EVP_PKEY_assign(pkey, id, oqs_key);
    return 1;
}

/**
* @brief verify item using given context/pkey.
*        As the pmeth digestverify is not available (opaque with no accessor)
*        perform the entire operation here, and return 1 to indicate no
*        further processing is required
*
*
* @param ctx MD context for digest and verification
* @param it  ASN1 item type
* @param asn internal asn item to verify
* @param alg signing algorithm
* @param signature to match on
* @param pkey contains public key for verification
*
* @return 1 on success or <=0 on error
*/
static int oqse_asn1_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                           X509_ALGOR *sigalg, ASN1_BIT_STRING *signature,
                           EVP_PKEY *pkey)
{
    OQS_KEY * oqs_key = (OQS_KEY *) EVP_PKEY_get0(pkey);
    const ASN1_OBJECT *obj;
    size_t inl = 0;
    unsigned char *buf_in = NULL;
    int ptype;
    int nid;
    int ret = 0;

    (void) ctx;

    /* Sanity check: make sure it is an OQS scheme with absent parameters */
    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    nid = OBJ_obj2nid(obj);

    // check if nid valid and is an OQS scheme with absent parameters
    if ( (oqse_nid2oqs(nid)<0) || (ptype != V_ASN1_UNDEF))
    {
        OQSEerr(OQSE_F_OQSE_ASN1_ITEM_VERIFY, OQSE_R_FATAL);
        goto err;
    }

    // convert it to buffer
    inl = ASN1_item_i2d(asn, &buf_in, it);

    if (!oqs_key || !oqs_key->s  || !oqs_key->pubkey || signature == NULL || buf_in == NULL)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_ITEM_VERIFY, OQSE_R_FATAL);
        goto err;
    }
    if (OQS_SIG_verify(oqs_key->s, buf_in, inl, signature->data, signature->length,
                             oqs_key->pubkey) != OQS_SUCCESS)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_ITEM_VERIFY, OQSE_R_FATAL);
        goto err;
    }
    ret = 1;

err:
    OPENSSL_clear_free((char *)buf_in, (unsigned int)inl);
    return ret;
}

/**
* @brief sign item using given context/pkey.
*        As the pmeth digestsign is not available (opaque with no accessor)
*        perform the entire operation here, and return 1 to indicate no
*        further processing is required
*
* @param ctx MD context for digest and signing
* @param it  ASN1 item type
* @param asn internal asn item to sign
* @param alg1 signing algorithm
* @param alg2 signing algorithm
* @param signature resulting signature as bit string
*
* @return 1 on success, <=0 on error
*/

int oqse_asn1_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn,
                         X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *signature)
{
    // pkey has the signing algo, so we do not have to do anything except return 3.
    int nid;
    size_t inl, outl, outll;
    EVP_PKEY * pkey;
    unsigned char *buf_in = NULL, *buf_out = NULL;
    int ret = 0;

    // nid was set in type when pkey was assigned using EVP_PKEY_assign(pkey, type, )
    pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(ctx));
    OQS_KEY * oqs_key = (OQS_KEY *) EVP_PKEY_get0(pkey);

    nid = EVP_PKEY_id(pkey);

    X509_ALGOR_set0(alg1, OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL);
    if (alg2)
    {
        X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_UNDEF, NULL);
    }

    // convert it to buffer
    inl = ASN1_item_i2d(asn, &buf_in, it);
    // get size
    outll = outl = oqs_key->s->length_signature;
    //worst case for all OQS algs, add tbslen and len (uint32_t) for variable length fields
    outll = outl + inl + sizeof(uint32_t);
    //worst case for all OQS algs, add tbslen and len (uint32_t) for variable length fields
    buf_out = OPENSSL_malloc((unsigned int)outll);
    if ((buf_in == NULL) || (buf_out == NULL))
    {
        outl = 0;
        OQSEerr(OQSE_F_OQSE_ASN1_ITEM_SIGN, OQSE_R_MALLOC_FAILURE);
        goto err;
    }
    if (OQS_SIG_sign(oqs_key->s, buf_out, &outl, buf_in, inl, oqs_key->privkey) != OQS_SUCCESS)
    {
        OQSEerr(OQSE_F_OQSE_ASN1_ITEM_SIGN, OQSE_R_FATAL);
        goto err;
    }
    OPENSSL_free(signature->data);
    signature->data = buf_out;
    buf_out = NULL;
    signature->length = outl;

    signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    ret = 1;

err:
    OPENSSL_clear_free((char *)buf_in, (unsigned int)inl);
    OPENSSL_clear_free((char *)buf_out, outll);
    return ret;
}

/**
* @brief 
*
* @param nid
* @param ameth
* @param pem_str
* @param info
*
* @return 
*/
int oqse_register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info)
{
    *ameth = EVP_PKEY_asn1_new(nid, 0, pem_str, info);
    if (!*ameth)
        return 0;

    EVP_PKEY_asn1_set_public(*ameth, oqse_asn1_pub_decode, oqse_asn1_pub_encode, oqse_asn1_pub_cmp, oqse_asn1_pub_print, NULL, oqse_asn1_bits);
    EVP_PKEY_asn1_set_private(*ameth, oqse_asn1_priv_decode, oqse_asn1_priv_encode, oqse_asn1_priv_print);
    //   EVP_PKEY_asn1_set_ctrl(*ameth, oqse_ctrl);
    EVP_PKEY_asn1_set_item(*ameth, oqse_asn1_item_verify, oqse_asn1_item_sign);

    EVP_PKEY_asn1_set_param(*ameth, 0, 0, 0, 0, oqse_asn1_cmp_parameters, 0);
    EVP_PKEY_asn1_set_security_bits(*ameth, oqse_asn1_security_bits);
    EVP_PKEY_asn1_set_free(*ameth, oqse_free);
    return 1;
}

/**
* @brief 
*
* @param id
* @param ameth
* @param flags
*
* @return 
*/
int oqse_register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags)
{
    const char *pem_str = NULL;
    const char *info = NULL;

    (void)flags;

    if (!ameth)
        return 0;

    if (!OBJ_add_sigid(id, NID_undef, id))
    {
        //errorf("OBJ_add_sigid() failed\n");
        return 0;
    }
    pem_str = OBJ_nid2sn(id);
    info = OBJ_nid2ln(id);
    return oqse_register_asn1_meth(id, ameth, pem_str, info);
}
