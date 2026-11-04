/*
 * Port of MIT krb5 1.22 plugins/kadm5_hook/test/main.c to krb5-rs's
 * kadm5_hook_plugin.h: "test" prints each call.  "refuse" refuses, before
 * the commit, any principal whose name starts with "blocked", and fails
 * every call after the commit.
 */
#include <krb5-rs/kadm5_hook_plugin.h>
#include <stdio.h>
#include <string.h>

#define KADM5_FAILURE 43787520

static void
log_call(const char *function, int stage, const char *princ)
{
    printf("%s: stage %s principal %s\n", function,
           stage == KRB5_RS_KADM5_HOOK_STAGE_PRECOMMIT ? "precommit" :
           "postcommit", princ);
    fflush(stdout);
}

static int
test_init(void **data)
{
    *data = NULL;
    printf("init\n");
    fflush(stdout);
    return 0;
}

static void
test_fini(void *data)
{
    (void)data;
    printf("fini\n");
    fflush(stdout);
}

static int
chpass(void *data, int stage, const char *princ, int keepold, int n_ks,
       const krb5_rs_key_salt_tuple *ks, const char *newpass)
{
    (void)data; (void)keepold; (void)n_ks; (void)ks; (void)newpass;
    log_call("chpass", stage, princ);
    return 0;
}

static int
create(void *data, int stage, const krb5_rs_kadm5_hook_princ *princ,
       long mask, int n_ks, const krb5_rs_key_salt_tuple *ks,
       const char *password)
{
    (void)data; (void)mask; (void)n_ks; (void)ks; (void)password;
    log_call("create", stage, princ->principal);
    return 0;
}

static int
modify(void *data, int stage, const krb5_rs_kadm5_hook_princ *princ,
       long mask)
{
    (void)data; (void)mask;
    log_call("modify", stage, princ->principal);
    return 0;
}

static int
remove_hook(void *data, int stage, const char *princ)
{
    (void)data;
    log_call("remove", stage, princ);
    return 0;
}

static int
rename_hook(void *data, int stage, const char *oprinc, const char *nprinc)
{
    (void)data; (void)nprinc;
    log_call("rename", stage, oprinc);
    return 0;
}

static int
alias_hook(void *data, int stage, const char *alias, const char *target)
{
    (void)data; (void)target;
    log_call("alias", stage, alias);
    return 0;
}

int
kadm5_hook_test_initvt(int maj_ver, int min_ver,
                       krb5_rs_kadm5_hook_vtable *vt)
{
    if (maj_ver != 1)
        return -1765328160;
    vt->name = "test";
    vt->init = test_init;
    vt->fini = test_fini;
    vt->chpass = chpass;
    vt->create = create;
    vt->modify = modify;
    vt->remove = remove_hook;
    if (min_ver >= 1)
        vt->rename = rename_hook;
    if (min_ver >= 2)
        vt->alias = alias_hook;
    return 0;
}

static int
refuse_create(void *data, int stage, const krb5_rs_kadm5_hook_princ *princ,
              long mask, int n_ks, const krb5_rs_key_salt_tuple *ks,
              const char *password)
{
    (void)data; (void)mask; (void)n_ks; (void)ks; (void)password;
    if (stage == KRB5_RS_KADM5_HOOK_STAGE_POSTCOMMIT)
        return KADM5_FAILURE;
    return strncmp(princ->principal, "blocked", 7) == 0 ? KADM5_FAILURE : 0;
}

int
kadm5_hook_refuse_initvt(int maj_ver, int min_ver,
                         krb5_rs_kadm5_hook_vtable *vt)
{
    (void)maj_ver; (void)min_ver;
    vt->name = "refuse";
    vt->create = refuse_create;
    return 0;
}

/* Fails to initialize, which is fatal. */
static int
bad_init(void **data)
{
    (void)data;
    return KADM5_FAILURE;
}

int
kadm5_hook_badinit_initvt(int maj_ver, int min_ver,
                          krb5_rs_kadm5_hook_vtable *vt)
{
    (void)maj_ver; (void)min_ver;
    vt->name = "badinit";
    vt->init = bad_init;
    return 0;
}
