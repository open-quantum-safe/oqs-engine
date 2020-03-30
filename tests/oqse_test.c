#define _GNU_SOURCE
#include <stdio.h>

#if defined(_WIN32)
#include <windows.h>
#include <openssl/applink.c>
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#include <stdlib.h>
#include <stddef.h>

#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>

#include "oqse.h"

BIO *bio_err = NULL;

#if defined(_WIN32)
#define CLOCK_MONOTONIC 0
LARGE_INTEGER getFILETIMEoffset()
{
    SYSTEMTIME s;
    FILETIME f;
    LARGE_INTEGER t;

    s.wYear = 1970;
    s.wMonth = 1;
    s.wDay = 1;
    s.wHour = 0;
    s.wMinute = 0;
    s.wSecond = 0;
    s.wMilliseconds = 0;
    SystemTimeToFileTime(&s, &f);
    t.QuadPart = f.dwHighDateTime;
    t.QuadPart <<= 32;
    t.QuadPart |= f.dwLowDateTime;
    return (t);
}

int clock_gettime(int X, struct timespec *tv)
{
    LARGE_INTEGER t;
    FILETIME f;
    double microseconds;
    static LARGE_INTEGER offset;
    static double frequencyToMicroseconds;
    static int initialized = 0;
    static int usePerformanceCounter = 0;

    if (!initialized)
    {
        LARGE_INTEGER performanceFrequency;
        initialized = 1;
        usePerformanceCounter = QueryPerformanceFrequency(&performanceFrequency);
        if (usePerformanceCounter)
        {
            QueryPerformanceCounter(&offset);
            frequencyToMicroseconds = (double)performanceFrequency.QuadPart / 1000000.;
        }
        else
        {
            offset = getFILETIMEoffset();
            frequencyToMicroseconds = 10.;
        }
    }
    if (usePerformanceCounter)
    {
        QueryPerformanceCounter(&t);
    }
    else
    {
        GetSystemTimeAsFileTime(&f);
        t.QuadPart = f.dwHighDateTime;
        t.QuadPart <<= 32;
        t.QuadPart |= f.dwLowDateTime;
    }
    t.QuadPart -= offset.QuadPart;
    microseconds = (double)t.QuadPart / frequencyToMicroseconds;
    t.QuadPart = microseconds;
    tv->tv_sec = (int64_t)t.QuadPart / 1000000;
    tv->tv_nsec = (long)t.QuadPart % 1000000 *1000;
    return (0);
}
#endif


/**
* @brief support function for time difference calculation
*
* @param diff   time between start and end
* @param start  start time
* @param end    end time
*/
static void tm_calc_diff(struct timespec * diff, struct timespec start, struct timespec end)
{
    if ((end.tv_nsec-start.tv_nsec)<0)
    {
        diff->tv_sec = end.tv_sec-start.tv_sec-1;
        diff->tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    } else {
        diff->tv_sec = end.tv_sec-start.tv_sec;
        diff->tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return;
}

/**
* @brief setup initial openssl load and err reporting
*/
static void oqse_test_init(void)
{
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    OPENSSL_init_crypto( OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_DYNAMIC, NULL);
}

/**
* @brief helper function to load openssl engine
*
* @param engine
*
* @return NULL on error or ENGINE ptr on success
*/
static ENGINE *try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e)
    {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0))
        {
            BIO_printf(bio_err, "engine ID %p failed to load\n", (void*)e);
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}

/**
* @brief setup engine by name and configure debug
*
* @param engine
* @param debug
*
* @return 
*/
static ENGINE *oqse_setup_engine(const char *engine, int debug)
{
    ENGINE *e = NULL;
    BIO_printf(bio_err, "Setting up engine (%s)\n", engine);
    if (engine)
    {
        if (strcmp(engine, "auto") == 0)
        {
            BIO_printf(bio_err, "enabling auto ENGINE support\n");
            ENGINE_register_all_complete();
            return NULL;
        }
        if ((e = ENGINE_by_id(engine)) == NULL && (e = try_load_engine(engine)) == NULL)
        {
            BIO_printf(bio_err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(bio_err);
            return NULL;
        }
        if (debug)
        {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
        }
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL))
        {
            BIO_printf(bio_err, "can't use that engine\n");
            ERR_print_errors(bio_err);
            ENGINE_free(e);
            return NULL;
        }

        BIO_printf(bio_err, "engine \"%s\" set.\n", ENGINE_get_id(e));
    }
    return e;
}

/**
* @brief 
*
* @param e
*/
void oqse_release_engine(ENGINE *e)
{
    if (e != NULL)
    {
        ENGINE_free(e);
    }
}

/**
* @brief calculate and return signature based on given PKEY context
*
* @param ctx    EVP_PKEY context
* @param start  start of data buffer
* @param l      length of data buffer
* @param sig    returned signature
*
* @return 0 on error or length of signature
*/
static size_t add_signature( EVP_PKEY_CTX *ctx, unsigned char *start, int l, unsigned char **sig )
{
    size_t siglen;

    if(ctx == NULL || start == NULL )
    {
        BIO_printf(bio_err, "sig failed 1\n");
        return 0;
    }
    EVP_PKEY_sign_init(ctx);
    if (EVP_PKEY_sign( ctx, NULL, &siglen, start, l)<=0)
    {
        BIO_printf(bio_err, "sig failed 2 \n");
        return 0;
    }
    *sig = calloc(1, siglen);
    if (!*sig)
    {
        BIO_printf(bio_err, "sig failed 3\n");
        return 0;
    }
    if (EVP_PKEY_sign( ctx, *sig, &siglen, start, l)<=0)
    {
        BIO_printf(bio_err, "sig failed 4\n");
        return 0;
    }
    return siglen;
}

/**
* @brief verify signature over given buffer with PKEY context
*
* @param ctx    EVP_PKEY context
* @param start  start of data buffer
* @param l      length of data buffer
* @param sig    signature to vewrify
* @param siglen length of signature
*
* @return 1 on success
*/
int verify_signature( EVP_PKEY_CTX * ctx, unsigned char *start, int l, unsigned char *sig, unsigned int siglen )
{
    if(ctx == NULL || start == NULL || sig == NULL)
    {
        BIO_printf(bio_err, "vfy failed 1\n");
        return 0;
    }
    if (EVP_PKEY_verify_init(ctx)!=1)
    {
        BIO_printf(bio_err, "vfy init failed\n");
        return 0;
    }
    if (EVP_PKEY_verify( ctx, sig, siglen, start, l )!=1)
    {
        //BIO_printf(bio_err, "vfy failed\n");
        return 0;
    }
    return 1;
}


/**
* @brief generate key pair for given NID, and save to temp file
*
* @param nid    OpenSSL NID
* @param engine ENGINE ptr
* @param pkey   EVP_PKEY to return
*/
void oqse_test_keygen(int nid, ENGINE *engine, EVP_PKEY **pkey)
{
    int st = 0;
#ifdef OQSE_TEST_GEN_FILE
    char * fname = NULL;
#endif
    unsigned char * d = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    /* Create the context for generating the parameters */
    if (!(pctx = EVP_PKEY_CTX_new_id(nid, engine)))
    {
        BIO_printf(bio_err, "%s: Failure in parameters ctx generation\n", OBJ_nid2sn(nid));
        goto qse_keygen_err;
    }

    if (!EVP_PKEY_paramgen_init(pctx))
    {
        BIO_printf(bio_err, "%s: Failure in paramgen init\n", OBJ_nid2sn(nid));
        goto qse_keygen_err;
    }

    st = EVP_PKEY_paramgen(pctx, &params);
    if (st != 1 && st != -2)
    {
        BIO_printf(bio_err, "%s: Failure in params generation (returned %d)\n", OBJ_nid2sn(nid), st);
        goto qse_keygen_err;
    }

    if (params != NULL)
    {
        kctx = EVP_PKEY_CTX_new(params, engine);
    }
    else
    {
        kctx = EVP_PKEY_CTX_new_id(nid, engine);
    }

    if (!kctx)
    {
        BIO_printf(bio_err,
                   "%s: Failure in keygen ctx generation\n", OBJ_nid2sn(nid));
        goto qse_keygen_err;
    }

    // NB: Important for QSE engine - set app data here so we can pick it up later in the actual
    // keygen operation
    EVP_PKEY_CTX_set_app_data(kctx, (void*) &nid);

    if (!EVP_PKEY_keygen_init(kctx))
    {
        BIO_printf(bio_err, "%s: Failure in keygen init\n", OBJ_nid2sn(nid));
        goto qse_keygen_err;
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, pkey))
    {
        BIO_printf(bio_err, "%s: Failure in key generation\n", OBJ_nid2sn(nid));
        goto qse_keygen_err;
    }

#ifdef OQSE_TEST_GEN_FILE
    mkdir("/tmp/oqse_test", S_IRWXU );
    if (asprintf(&fname,"/tmp/oqse_test/%s_prv.pem", OBJ_nid2sn(nid))<0)
        goto qse_keygen_err;

    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        if (f)
        {
            PEM_write_PrivateKey(f, *pkey, NULL, NULL, 0, NULL, NULL);
            fclose(f);
        }
        free(fname);
        fname = NULL;
    }

    if (asprintf(&fname,"/tmp/oqse_test/%s_pub.pem", OBJ_nid2sn(nid))<0)
        goto qse_keygen_err;

    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        PEM_write_PUBKEY(f, *pkey);
        fclose(f);
        free(fname);
        fname = NULL;
    }
#endif

qse_keygen_err:
    ERR_print_errors(bio_err);
    if (d)
        free(d);
    if (params)
        EVP_PKEY_free(params);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
}

/**
* @brief create basic X509 CSR and sign with given EVP_PKEY
*
* @param req    X509 CSR to return
* @param pkey   EVP_PKEY signing key
* @param engine OpenSSL ENGINE ptr
*
* @return 1 on success
*/
static int oqse_csr_sign(X509_REQ **req, EVP_PKEY *pkey, ENGINE * engine)
{
    const EVP_MD *evpmd = NULL;
    int nid = EVP_PKEY_id(pkey);
    (void) engine;
    int bits = EVP_PKEY_security_bits(pkey);

    if ( bits >= 1 && bits <= 256)
        evpmd = EVP_sha256();
    else if ( bits >= 257 && bits <= 384 )
        evpmd = EVP_sha384();
    else
        evpmd = EVP_sha512();

    *req = X509_REQ_new();

    if( *req )
    {
        X509_NAME * n = X509_NAME_new();

        X509_REQ_set_version( *req, 0L );
        X509_REQ_set_pubkey( *req, pkey );

        X509_NAME_add_entry_by_txt( n,"C", MBSTRING_ASC, (const unsigned char*)"AU",-1,-1,0);
        X509_NAME_add_entry_by_txt( n,"CN", MBSTRING_ASC, (const unsigned char*) OBJ_nid2sn(nid),-1,-1,0);

        X509_REQ_set_subject_name(*req, n);
        /*  sign the request */
        if (!engine || !EVP_PKEY_set1_engine(pkey, engine))
        {
            // TTD error to bio
            printf("%s(%d)\n", __func__, __LINE__ );
        }
        X509_NAME_free(n);
        if( X509_REQ_sign( *req, pkey, evpmd ))
        {
            BIO_printf(bio_err, "%s: successfully signed CSR\n", OBJ_nid2sn(nid));
            return 1;
        }
        BIO_printf(bio_err, "%s: failed to sign CSR\n", OBJ_nid2sn(nid));
        ERR_print_errors(bio_err);
        X509_REQ_free( *req );
        *req = NULL;
    }
    return 0;
}

/**
* @brief verify given CSR signature. Note, the PKEY already has it's engine set
*        so *engine not actually required here.
*
* @param req OpenSSL CSR
* @param pkey EVP_PKEY to use
* @param engine OpenSSL ENGINE ptr
*
* @return  1 on success
*/
static int oqse_csr_verify(X509_REQ *req, EVP_PKEY *pkey, ENGINE * engine)
{
    int nid = EVP_PKEY_id(pkey);

    (void) engine;

    if( X509_REQ_verify( req, pkey))
    {
            BIO_printf(bio_err, "%s: successfully verified CSR\n", OBJ_nid2sn(nid));
            return 1;
    }
    BIO_printf(bio_err, "%s: verification failed on CSR\n", OBJ_nid2sn(nid));
    ERR_print_errors(bio_err);
    X509_REQ_free( req );
    return 0;
}


/**
* @brief 
*
* @param nid
* @param pkey
* @param engine
*
* @return 
*/
static int oqse_keygen(int nid, EVP_PKEY **pkey, ENGINE *engine)
{
    struct timespec tm1;
    struct timespec tm2;
    struct timespec tmd;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    clock_gettime(CLOCK_MONOTONIC, &tm1);

    /* Create the context for generating the parameters */
    if (!(pctx = EVP_PKEY_CTX_new_id(nid, engine)))
    {
        BIO_printf(bio_err, "%s: Failure in parameters ctx generation\n", OBJ_nid2sn(nid));
        goto oqse_keygen_err;
    }

    ERR_set_mark();
    if (!EVP_PKEY_paramgen_init(pctx))
    {
        BIO_printf(bio_err, "%s: Failure in paramgen init\n", OBJ_nid2sn(nid));
        goto oqse_keygen_err;
    }
    ERR_pop_to_mark();

    /* Set the paramgen parameters according to the type */
    ERR_set_mark();
    switch (EVP_PKEY_paramgen(pctx, &params))
    {
        case -2:
        case  1:
            break;
        default:
            BIO_printf(bio_err, "%s: Failure in params generation\n", OBJ_nid2sn(nid));
            goto oqse_keygen_err;
            break;
    }
    ERR_pop_to_mark();

    if (params != NULL)
    {
        kctx = EVP_PKEY_CTX_new(params, engine);
    }
    else
    {
        kctx = EVP_PKEY_CTX_new_id(nid, engine);
    }

    // set app data here so we can pick it up later - used inside keygen in the engine
    EVP_PKEY_CTX_set_app_data(kctx, (void*) &nid);
    if (!kctx)
    {
        BIO_printf(bio_err, "%s: Failure in keygen ctx generation\n", OBJ_nid2sn(nid));
        goto oqse_keygen_err;
    }
    if (!EVP_PKEY_keygen_init(kctx))
    {
        BIO_printf(bio_err, "%s: Failure in keygen init\n", OBJ_nid2sn(nid));
        goto oqse_keygen_err;
    }

    /* Generate the key */
    if (!EVP_PKEY_keygen(kctx, pkey))
    {
        BIO_printf(bio_err, "%s: Failure in key generation\n", OBJ_nid2sn(nid));
        goto oqse_keygen_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    tm_calc_diff( &tmd, tm1, tm2);
    BIO_printf(bio_err, "    KeyGen: %.2lld.%.9ld\n", (long long)tmd.tv_sec, tmd.tv_nsec);

    return 1;

oqse_keygen_err:
    if (params)
        EVP_PKEY_free(params);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (kctx)
        EVP_PKEY_CTX_free(kctx);
    return 0;
}

/**
* @brief 
*
* @param nid
* @param engine
*/
int oqse_asn1_wrapper(int nid, ENGINE *engine)
{
    EVP_PKEY * pkey = NULL;
#ifdef OQSE_TEST_GEN_FILE
    char * fname = NULL;
#endif
    X509_REQ *req = NULL;

    // 1. create key pair for given nid
    oqse_keygen( nid, &pkey, engine );
    if (!pkey)
    {
        BIO_printf(bio_err, "%s: Failure to create key pair\n", OBJ_nid2sn(nid));
        return 1;
    }

    // 2. dump PEMs just for good mesaure
    // EVP_PKEY_print_private(bio_err, pkey, 0, 0);
    // EVP_PKEY_print_public(bio_err, pkey, 0, 0);

    // 3. write to file
#ifdef OQSE_TEST_GEN_FILE
    mkdir("/tmp/oqse_test_keygen", S_IRWXU );
    if (asprintf(&fname,"/tmp/oqse_test_keygen/%s_prv.pem", OBJ_nid2sn(nid))<0)
        return 1;

    mkdir("/tmp/oqse_test_asn1", S_IRWXU );
    if (asprintf(&fname,"/tmp/oqse_test_asn1/%s_prv.pem", OBJ_nid2sn(nid))<0)
        return 1;

    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        if (f)
        {
            PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
            fclose(f);
        }
        free(fname);
        fname = NULL;
    }

    if (asprintf(&fname,"/tmp/oqse_test_asn1/%s_pub.pem", OBJ_nid2sn(nid))<0)
        return 1;
    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        PEM_write_PUBKEY(f, pkey);
        fclose(f);
        free(fname);
        fname = NULL;
    }
#endif
    // create certificate signing reqs with given pkey
    if (!oqse_csr_sign(&req, pkey, engine))
    {
        BIO_printf(bio_err, "%s: Failure to sign X509REQ\n", OBJ_nid2sn(nid));
        return 1;
    }
    // create certificate signing reqs with given pkey
    if (!oqse_csr_verify(req, pkey, engine))
    {
        BIO_printf(bio_err, "%s: Failure to verify X509REQ\n", OBJ_nid2sn(nid));
        return 1;
    }
    return 0;
}

/**
* @brief 
*
* @param nid
* @param engine
*/
int oqse_keygen_wrapper(int nid, ENGINE *engine)
{
#ifdef OQSE_TEST_GEN_FILE
    char * fname = NULL;
#endif
    unsigned char d[1024]  = {0};
    size_t siglen = 0;
    unsigned char * sig = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    OQS_KEY *oqs_key = NULL;
    struct timespec tm1;
    struct timespec tm2;
    struct timespec tmd;
    EVP_PKEY *pkey = NULL;
    int ret = 1;

    // 1. create key pair for given nid
    oqse_keygen( nid, &pkey, engine );
    if (!pkey)
    {
        BIO_printf(bio_err, "%s: Failure to create key pair\n", OBJ_nid2sn(nid));
        return ret;
    }

    // 2. dump PEMs just for good mesaure
    //EVP_PKEY_print_private(bio_err, pkey, 0, 0);
    //EVP_PKEY_print_public(bio_err, pkey, 0, 0);

    // 3. write to file
#ifdef OQSE_TEST_GEN_FILE
    mkdir("/tmp/qse_test_keygen", S_IRWXU );
    if (asprintf(&fname,"/tmp/qse_test_keygen/%s_prv.pem", OBJ_nid2sn(nid))<0)
        return ret;

    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        if (f)
        {
            PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
            fclose(f);
        }
        free(fname);
        fname = NULL;
    }
    if (asprintf(&fname,"/tmp/qse_test_keygen/%s_pub.pem", OBJ_nid2sn(nid))<0)
        return ret;
    if (fname)
    {
        FILE *f = fopen(fname, "wb");
        PEM_write_PUBKEY(f, pkey);
        fclose(f);
        free(fname);
        fname = NULL;
    }
#endif
    // 4. sign and verify, including test bad verification (+/- testing)
    sctx = EVP_PKEY_CTX_new(pkey, engine); // create a  new context with given key
    // malloc d to be size of message + size of 
    oqs_key = (OQS_KEY*) EVP_PKEY_get0(pkey);
    if (!oqs_key)
    {
        goto evp_keygen_err;
    }
    RAND_bytes(d, sizeof(d));
    clock_gettime(CLOCK_MONOTONIC, &tm1);
    siglen = add_signature( sctx, d, sizeof(d), &sig );
    if (!siglen)
    {
        BIO_printf(bio_err,
                   "%s: Failure in signature\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    tm_calc_diff( &tmd, tm1, tm2);
    BIO_printf(bio_err, "      Sign: %.2lld.%.9ld\n", (long long)tmd.tv_sec, tmd.tv_nsec);

    clock_gettime( CLOCK_MONOTONIC, &tm1);
    if (!verify_signature( sctx, d, sizeof(d), sig, siglen ))
    {
        BIO_printf(bio_err,
                   "%s: Failure in verify\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    //printf("Signature verification test passed.\n");
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    tm_calc_diff( &tmd, tm1, tm2);
    BIO_printf(bio_err, "   Verify+: %.2lld.%.9ld\n", (long long) tmd.tv_sec, tmd.tv_nsec);

    clock_gettime(CLOCK_MONOTONIC, &tm1);
    d[0]++; // corrupt results and recheck
    if (verify_signature( sctx, d, sizeof(d), sig, siglen ))
    {
        BIO_printf(bio_err,
                   "%s: Failure in verify\n", OBJ_nid2sn(nid));
        goto evp_keygen_err;
    }
    clock_gettime(CLOCK_MONOTONIC, &tm2);
    tm_calc_diff( &tmd, tm1, tm2);
    BIO_printf(bio_err, "   Verify-: %.2lld.%.9ld\n", (long long) tmd.tv_sec, tmd.tv_nsec);
    //printf("Signature verification force fail test passed.\n");
    if (sig)
        free(sig);
    sig = NULL;
    ret = 0;

evp_keygen_err:
    ERR_print_errors(bio_err);
    if (sctx)
        EVP_PKEY_CTX_free(sctx);
    return ret;
}

/**
* @brief oqse_test utility to demonstrate ENGINE usage and setup.
*
* @param argc
* @param argv[]
*
* @return 
*/
int main(int argc, char *argv[])
{
    int i = 0;
    int ret = 0;
    int errors = 0;
    const char *engine_id = "liboqse";

    (void) argc;
    (void) argv;

    oqse_test_init();

    BIO_printf(bio_err, "OQSE OpenSSL Engine Test %s\n", "1.0");
    if (!oqse_setup_engine(engine_id, 1))
    {
        BIO_printf(bio_err, "Engine not found. Please ensure OPENSSL_ENGINES path is set correctly\n");
        return 1;
    }

    // we want to get these via openssl now, not OQS
    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        const char *sname=NULL;
        int nid=0;

        sname = OQS_SIG_alg_identifier(i);
        nid = OBJ_sn2nid(sname);
        BIO_printf(bio_err, "Alg: %s (nid=%d)\n", sname, nid);

        ret += oqse_keygen_wrapper(nid, ENGINE_by_id(engine_id));
        ret += oqse_asn1_wrapper(nid, ENGINE_by_id(engine_id));
        if (ret)
        {
            errors++;
            BIO_printf(bio_err, "Alg: %s (nid=%d) test FAILED (total %d)\n", sname, nid, errors);
        }
        ret = 0;
    }
 //   return errors;
    return 0;
}
