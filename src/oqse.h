#ifndef __OQSE_H__
#define __OQSE_H__

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>

// Use Senetas Enterprise ID for interim OID reference.
#ifndef OQSE_OID_SIG_BASE
#define OQSE_OID_SIG_BASE "1.3.6.1.4.1.3534.100"
#endif

/**
* @brief OQS context used pkey data
*/
typedef struct
{
  OQS_SIG *s;          /**< sig alg */
  uint8_t *pubkey;     /**< public key */
  uint8_t *privkey;    /**< private key */
  int security_bits;   /**< estimated security bits based in nist level */
} OQS_KEY;

/**
* @brief OQS key type enum
*/
typedef enum
{
    KEY_TYPE_PUBLIC,
    KEY_TYPE_PRIVATE,
} oqs_key_type_t;

/**
* @brief global struct tie pmeth and ameth data together for each registered nid
*/
typedef struct qse_global_s
{
    int nid;                     /**< numerical identifier for oqs signaturee alg */
    EVP_PKEY_METHOD *pmeth;      /**< EVP_PKEY method for given nid */
    EVP_PKEY_ASN1_METHOD *ameth; /**< ASN1 method for given nid */
} oqse_global_t;

// track relationship between NIDS and OQS alg numbers
extern int * oqse_pkey_meth_nids;
extern int * oqse_pkey_asn1_meth_nids;
extern oqse_global_t * oqse_global;

int oqse_nid2oqs(int nid);

// asn1 methods
int oqse_register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags);
int oqse_pkey_ameths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);

// pkey meths

int oqse_register_pmeth(int id, EVP_PKEY_METHOD **pmeth, int flags);
int oqse_pkey_pmeths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);

// needed by asn1 sign/verify item calls
int oqse_pmeth_digestsign(EVP_MD_CTX *ctx, unsigned char *sig,
                               size_t *siglen, const unsigned char *tbs,
                               size_t tbslen);
int oqse_pmeth_digestverify(EVP_MD_CTX *ctx, const unsigned char *sig,
                                 size_t siglen, const unsigned char *tbs,
                                 size_t tbslen);

#if defined(_WIN32)
int asprintf(char **ret, const char *format, ...);
#endif

#endif /* __OQSE_H__ */
