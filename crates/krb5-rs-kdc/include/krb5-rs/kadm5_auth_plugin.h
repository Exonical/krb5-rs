/*
 * krb5-rs-kadmind kadm5_auth module interface.
 *
 * Modules are configured as in MIT krb5 1.22:
 *
 *     [plugins]
 *         kadm5_auth = {
 *             module = name:path/to/module.so
 *             enable_only = name
 *             disable = self
 *         }
 *
 * and export kadm5_auth_<name>_initvt, which kadmind calls with major
 * version 1 and minor version 0.  The vtable differs from MIT's
 * kadm5_auth_plugin.h: principals are passed as unparsed strings and no
 * krb5_context is given, because krb5-rs-kadmind has no MIT library context.
 *
 * kadmind serves requests on one thread, so a module is never called
 * concurrently.
 */
#ifndef KRB5_RS_KADM5_AUTH_PLUGIN_H
#define KRB5_RS_KADM5_AUTH_PLUGIN_H

#include <stdint.h>

#define KRB5_RS_PLUGIN_NO_HANDLE (-1765328135) /* KRB5_PLUGIN_NO_HANDLE */

/* MIT's OP_* numbers (kadmin/server/auth.h). */
enum {
    KADM5_AUTH_OP_ADDPRINC = 1,
    KADM5_AUTH_OP_MODPRINC = 2,
    KADM5_AUTH_OP_SETSTR = 3,      /* p1, s1 = key, s2 = value */
    KADM5_AUTH_OP_CPW = 4,         /* p1 */
    KADM5_AUTH_OP_CHRAND = 5,      /* p1 */
    KADM5_AUTH_OP_SETKEY = 6,      /* p1 */
    KADM5_AUTH_OP_PURGEKEYS = 7,   /* p1 */
    KADM5_AUTH_OP_DELPRINC = 8,    /* p1 */
    KADM5_AUTH_OP_RENPRINC = 9,    /* p1 = source, p2 = destination */
    KADM5_AUTH_OP_GETPRINC = 10,   /* p1 */
    KADM5_AUTH_OP_GETSTRS = 11,    /* p1 */
    KADM5_AUTH_OP_EXTRACT = 12,    /* p1 */
    KADM5_AUTH_OP_LISTPRINCS = 13,
    KADM5_AUTH_OP_ADDPOL = 14,     /* s1 = policy, pol */
    KADM5_AUTH_OP_MODPOL = 15,     /* s1 = policy, pol */
    KADM5_AUTH_OP_DELPOL = 16,     /* s1 = policy */
    KADM5_AUTH_OP_GETPOL = 17,     /* s1 = policy, s2 = client's policy */
    KADM5_AUTH_OP_LISTPOLS = 18,
    KADM5_AUTH_OP_IPROP = 19,
    KADM5_AUTH_OP_ADDALIAS = 20    /* p1 = alias, p2 = target */
};

/* ADDPRINC/MODPRINC: p1 and the requested entry. */
typedef struct {
    long mask;                  /* KADM5_* principal mask */
    int32_t attributes;
    int32_t max_life;
    int32_t max_renewable_life;
    int32_t princ_expire_time;
    int32_t pw_expiration;
    const char *policy;         /* or NULL */
} krb5rs_kadm5_auth_princ;

typedef struct {
    long mask;                  /* KADM5_* policy mask */
    int32_t pw_min_life;
    int32_t pw_max_life;
    int32_t pw_min_length;
    int32_t pw_min_classes;
    int32_t pw_history_num;
} krb5rs_kadm5_auth_policy;

/* struct kadm5_auth_restrictions. */
typedef struct {
    long mask;
    int32_t require_attrs;
    int32_t forbid_attrs;
    int32_t princ_lifetime;
    int32_t pw_lifetime;
    int32_t max_life;
    int32_t max_renewable_life;
    const char *policy;
} krb5rs_kadm5_auth_restrictions;

typedef struct {
    const char *name;
    /* acl_file is the realm's acl_file.  Return KRB5_RS_PLUGIN_NO_HANDLE to
     * be skipped, another nonzero value to stop kadmind. */
    int (*init)(const char *acl_file, void **data);
    void (*fini)(void *data);
    /* Return 0 to authorize, KRB5_RS_PLUGIN_NO_HANDLE for no opinion, or
     * another value to refuse.  Unused arguments are NULL.  For ADDPRINC
     * and MODPRINC, *rs may be set; it is freed with free_restrictions. */
    int (*authorize)(void *data, int opcode, const char *client,
                     const char *p1, const char *p2, const char *s1,
                     const char *s2, const krb5rs_kadm5_auth_princ *princ,
                     const krb5rs_kadm5_auth_policy *pol,
                     krb5rs_kadm5_auth_restrictions **rs);
    /* Called after each kadm5 request. */
    void (*end)(void *data);
    void (*free_restrictions)(void *data, krb5rs_kadm5_auth_restrictions *rs);
} krb5rs_kadm5_auth_vtable;

typedef int (*krb5rs_kadm5_auth_initvt_fn)(int maj_ver, int min_ver,
                                          krb5rs_kadm5_auth_vtable *vt);

#endif
