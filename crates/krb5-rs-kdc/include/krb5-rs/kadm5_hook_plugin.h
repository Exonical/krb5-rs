/*
 * krb5-rs kadm5_hook module interface.
 *
 * Modules are configured as in MIT krb5 1.22:
 *
 *     [plugins]
 *         kadm5_hook = {
 *             module = name:path/to/module.so
 *         }
 *
 * and export kadm5_hook_<name>_initvt, which krb5-rs-kadmind and
 * krb5-rs-kdb call with major version 1 and minor version 2 (rename and
 * alias are present).  The vtable differs from MIT's kadm5_hook_plugin.h:
 * principals are unparsed strings and no krb5_context is given.
 *
 * Each callback runs at KRB5_RS_KADM5_HOOK_STAGE_PRECOMMIT, where a nonzero
 * return (a kadm5 or com_err code) aborts the change, and at
 * KRB5_RS_KADM5_HOOK_STAGE_POSTCOMMIT, where a nonzero return is logged.
 * Module callbacks never run at once.
 */
#ifndef KRB5_RS_KADM5_HOOK_PLUGIN_H
#define KRB5_RS_KADM5_HOOK_PLUGIN_H

#include <stdint.h>

enum {
    KRB5_RS_KADM5_HOOK_STAGE_PRECOMMIT = 0,
    KRB5_RS_KADM5_HOOK_STAGE_POSTCOMMIT = 1
};

/* krb5_key_salt_tuple. */
typedef struct {
    int32_t enctype;
    int32_t salttype;
} krb5_rs_key_salt_tuple;

/* The requested kadm5_principal_ent_t fields. */
typedef struct {
    const char *principal;
    int32_t attributes;
    int32_t max_life;
    int32_t max_renewable_life;
    int32_t princ_expire_time;
    int32_t pw_expiration;
    const char *policy;         /* or NULL */
} krb5_rs_kadm5_hook_princ;

typedef struct krb5_rs_kadm5_hook_vtable {
    const char *name;
    int (*init)(void **data);
    void (*fini)(void *data);
    int (*chpass)(void *data, int stage, const char *princ, int keepold,
                  int n_ks_tuple, const krb5_rs_key_salt_tuple *ks_tuple,
                  const char *newpass);
    int (*create)(void *data, int stage, const krb5_rs_kadm5_hook_princ *princ,
                  long mask, int n_ks_tuple,
                  const krb5_rs_key_salt_tuple *ks_tuple, const char *password);
    int (*modify)(void *data, int stage, const krb5_rs_kadm5_hook_princ *princ,
                  long mask);
    int (*remove)(void *data, int stage, const char *princ);
    /* Minor version 1. */
    int (*rename)(void *data, int stage, const char *oprinc,
                  const char *nprinc);
    /* Minor version 2. */
    int (*alias)(void *data, int stage, const char *alias,
                 const char *target);
} krb5_rs_kadm5_hook_vtable;

int kadm5_hook_NAME_initvt(int maj_ver, int min_ver,
                           krb5_rs_kadm5_hook_vtable *vt);

#endif
