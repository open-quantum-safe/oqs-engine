#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>
#include "oqse_err.h"
#include "oqse.h"

int * oqse_pkey_meth_nids = NULL;
int * oqse_pkey_asn1_meth_nids = NULL;
oqse_global_t * oqse_global = NULL;


/**
* @brief Obtain OQS alg enum from openssl NID
*
* @param nid    Openssl NID
*
* @return       OQS algorithm enumerated value
*/
int oqse_nid2oqs(int nid)
{
    int i=0;

    if (!oqse_global)
        return -1;

    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        if ((oqse_global+i)->nid == nid)
        {
            return i;
        }
    }
    OQSEerr(OQSE_F_OQSE_NID2OQS, OQSE_R_BAD_NID);
    return -1;
}

/**
* @brief regsiter a new OBJ with openssl
*
* @param oid_str   object OID
* @param sn        short name
* @param ln        long name
*
* @return new NID or 0 on error
*/
static int oqse_register_nid(const char *oid_str, const char *sn, const char *ln)
{
    int new_nid = NID_undef;

    if (NID_undef != (new_nid = OBJ_sn2nid(sn)) )
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NID, OQSE_R_ALREADY_REGISTERED);
        return new_nid;
    }

    new_nid = OBJ_create(oid_str, sn, ln);
    if (new_nid == NID_undef)
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NID, OQSE_R_OBJ_CREATE_FAILED);
        return 0;
    }

    ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
    if ( !obj )
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NID, OQSE_R_OBJ_RETRIEVE_FAILED);
        return 0;
    }
    return new_nid;
}

/**
* @brief Scan through all OQS signature algorithms, and register with openssl
*        This routine creates a mapping between openssl NIDS and OQS identifier
*
* @return 0 on error
*/
static int oqse_register_nids(void)
{
    int i = 0;
    char * oid=NULL;

    oqse_global = calloc(OQS_SIG_algs_length, sizeof(oqse_global_t));
    if (!oqse_global)
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NIDS, OQSE_R_CALLOC_FAILED);
        return 0;
    }

    oqse_pkey_meth_nids = calloc(OQS_SIG_algs_length, sizeof(int));
    if (!oqse_pkey_meth_nids)
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NIDS, OQSE_R_CALLOC_FAILED);
        return 0;
    }

    oqse_pkey_asn1_meth_nids = calloc(OQS_SIG_algs_length, sizeof(int));
    if (!oqse_pkey_asn1_meth_nids)
    {
        OQSEerr(OQSE_F_OQSE_REGISTER_NIDS, OQSE_R_CALLOC_FAILED);
        return 0;
    }
    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        const char *sname=NULL;
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_identifier(i));

        if (!sig)
        {
            OQSEerr(OQSE_F_OQSE_REGISTER_NIDS, OQSE_R_SIGN_NEW_FAILED);
            return 0;
        }

        sname = OQS_SIG_alg_identifier(i);

        if (sname == NULL)
            sname = "unknown";

        if (asprintf(&oid,"%s.%d", OQSE_OID_SIG_BASE, i+1)<0)
        {
            return 0;
        }
        (oqse_global+i)->nid = oqse_register_nid( oid, sname, sname );
        *(oqse_pkey_meth_nids+i) = (oqse_global+i)->nid;
        *(oqse_pkey_asn1_meth_nids+i) = (oqse_global+i)->nid;

        free(oid);

        if ((oqse_global+i)->nid == NID_undef)
        {
            OQSEerr(OQSE_F_OQSE_REGISTER_NIDS, OQSE_R_NID_UNDEF);
            return 0;
        }
    }
    return 1;
}

/**
* @brief release all memory alloc'd during nid registration
*
* @return NONE
*/
static void oqse_unregister_nids(void)
{
    if (oqse_global)
        free(oqse_global);

    if (oqse_pkey_meth_nids)
        free(oqse_pkey_meth_nids);

    if (oqse_pkey_asn1_meth_nids)
        free(oqse_pkey_asn1_meth_nids);
}

/**
* @brief openSSL engine init function
*
* @param e - openSSL Engine
*
* @return 
*/
static int oqse_e_init(ENGINE *e)
{
    (void)e;
    return 1;
}

/**
* @brief openSSL engine destroy function
*
* @param e - openSSL Engine
*
* @return 
*/
static int oqse_e_destroy(ENGINE *e)
{
    (void)e;

    ERR_unload_OQSE_strings();
    oqse_unregister_nids();
    OBJ_cleanup(); // cleans up openssl internal object table if OBJ_Create is used
    return 1;
}

/**
* @brief openSSL engine finish function
*
* @param e - openSSL Engine
*
* @return 
*/
static int oqse_e_finish(ENGINE *e)
{
    (void)e;
    return 1;
}

/**
* @brief 
*
* @param e
* @param cmd
* @param i
* @param p
* @param f
*
* @return 
*/
int oqse_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    (void)e;
    (void)cmd;
    (void)i;
    (void)p;
    (void)f;
    return 1;
}

/**
* @brief main entry point for openSSL Engine bind sequence
*
* @param e - openSSL engine
* @param id
*
* @return 
*/
static int oqse_bind_helper(ENGINE *e)
{
    int i = 0;

    int ret = 0;

    if (!ERR_load_OQSE_strings())
    {
        goto end;
    }

    if (!ENGINE_set_id(e, "liboqse"))
    {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_SET_FAILED);
        goto end;
    }

    if (!ENGINE_set_name(e, "liboqs openSSL Engine"))
    {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_NAME_FAILED);
        goto end;
    }

    if(!ENGINE_set_init_function(e, oqse_e_init)) {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_INIT_FAILED);
        goto end;
    }
    if (!ENGINE_set_ctrl_function(e, oqse_control_func))
    {
        goto end;
    }

    if(!ENGINE_set_destroy_function(e, oqse_e_destroy))
    {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_SET_DESTROY_FAILED);
        goto end;
    }
    if(!ENGINE_set_finish_function(e, oqse_e_finish)) {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_SET_FINISH_FAILED);
        goto end;
    }


    if (!oqse_register_nids())
    {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_REGISTER_NIDS_FAILED);
        goto end;
    }

    for (i = 0; i < OQS_SIG_algs_length; i++)
    {
        // register ameths (asn1)
        if (!oqse_register_ameth((oqse_global+i)->nid, &((oqse_global+i)->ameth), 0))
        {
            OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_REGISTER_AMETH_FAILED);
            return 0;
        }

        // register pmeth (sign/verify)
        if (!oqse_register_pmeth((oqse_global+i)->nid, &((oqse_global+i)->pmeth), 0))
        {
            OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_REGISTER_PMETH_FAILED);
            return 0;
        }
    }

    // set function to get ameths
    if (!ENGINE_set_pkey_asn1_meths(e, oqse_pkey_ameths)) {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_AMETH_FAILED);
        goto end;
    }

    // set function to get pmeths
    if (!ENGINE_set_pkey_meths(e, oqse_pkey_pmeths)) {
        OQSEerr(OQSE_F_OQSE_BIND_HELPER, OQSE_R_ENGINE_BIND_PMETH_FAILED);
        goto end;
    }

    ret = 1;
end:
    return ret;
}


#ifndef OPENSSL_NO_DYNAMIC_ENGINE
int oqse_bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, "liboqse") != 0))
        return 0;
    if (!oqse_bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(oqse_bind_fn)
#endif

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *ENGINE_oqse(void)
{
    ENGINE *eng = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!oqse_bind_helper(eng)) {
        ENGINE_free(ret);
        return NULL;
    }
    return eng;
}
#endif
