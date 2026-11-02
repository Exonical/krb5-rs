/*
 * Test kadm5_auth modules, after MIT's plugins/kadm5_auth/test/main.c.
 * "welcomer" authorizes some operations, "bouncer" refuses some, and
 * "limiter" returns restrictions.  welcomer's end appends a line to the file
 * named by KADM5_AUTH_TEST_ENDS (MIT's welcomer counts in a string
 * attribute).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "krb5-rs/kadm5_auth_plugin.h"

#define KADM5_MAX_LIFE 0x000020
#define KADM5_POLICY 0x000800
#define KADM5_MAX_RLIFE 0x002000
#define KADM5_PW_MIN_LIFE 0x008000
#define KADM5_PW_MIN_LENGTH 0x010000
#define DENY 13 /* EPERM-like */
#define NO_HANDLE KRB5_RS_PLUGIN_NO_HANDLE

/* Length of the first component of "a/b@R". */
static size_t
first_len(const char *p)
{
    return strcspn(p, "/@");
}

/* Number of components of "a/b@R". */
static int
ncomps(const char *p)
{
    int n = 1;

    for (; *p != '\0' && *p != '@'; p++)
        n += (*p == '/');
    return n;
}

static int
welcomer(void *data, int op, const char *client, const char *p1,
         const char *p2, const char *s1, const char *s2,
         const krb5rs_kadm5_auth_princ *princ,
         const krb5rs_kadm5_auth_policy *pol,
         krb5rs_kadm5_auth_restrictions **rs)
{
    switch (op) {
    case KADM5_AUTH_OP_ADDPRINC:
        return ((princ->mask & KADM5_POLICY) && princ->policy != NULL &&
                strcmp(princ->policy, "VIP") == 0) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_MODPRINC:
        return (princ->mask == KADM5_MAX_RLIFE) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_SETSTR:
        return (strcmp(s1, "note") == 0) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_DELPRINC:
        return (*p1 == 'd') ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_RENPRINC:
        return (first_len(p1) == first_len(p2)) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_ADDPOL:
        return ((pol->mask & KADM5_PW_MIN_LENGTH) &&
                pol->pw_min_length == 3) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_MODPOL:
        return (pol->mask == KADM5_PW_MIN_LIFE) ? 0 : NO_HANDLE;
    case KADM5_AUTH_OP_GETPOL:
        return (s2 != NULL && strlen(s1) == strlen(s2)) ? 0 : NO_HANDLE;
    }
    return NO_HANDLE;
}

static void
welcomer_end(void *data)
{
    const char *path = getenv("KADM5_AUTH_TEST_ENDS");
    FILE *f;

    if (path == NULL)
        return;
    f = fopen(path, "a");
    if (f != NULL) {
        fputs("end\n", f);
        fclose(f);
    }
}

static int
bouncer(void *data, int op, const char *client, const char *p1,
        const char *p2, const char *s1, const char *s2,
        const krb5rs_kadm5_auth_princ *princ,
        const krb5rs_kadm5_auth_policy *pol,
        krb5rs_kadm5_auth_restrictions **rs)
{
    switch (op) {
    case KADM5_AUTH_OP_ADDPRINC:
        return (princ->mask & KADM5_MAX_LIFE) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_MODPRINC:
        return (ncomps(p1) % 2 == 0) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_SETSTR:
        return (s2 != NULL && strlen(s2) > 10) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_DELPRINC:
        return (strstr(p1, "nodelete") != NULL) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_RENPRINC:
        return (*p1 == 'a') ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_ADDPOL:
        return (strlen(s1) <= 3) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_MODPOL:
        return ((pol->mask & KADM5_PW_MIN_LIFE) &&
                pol->pw_min_life > 10) ? DENY : NO_HANDLE;
    case KADM5_AUTH_OP_GETPOL:
        return (*s1 == 'x') ? DENY : NO_HANDLE;
    }
    return NO_HANDLE;
}

/* Authorizes addprinc of "lim*" but caps max_life at 3600. */
static int
limiter(void *data, int op, const char *client, const char *p1,
        const char *p2, const char *s1, const char *s2,
        const krb5rs_kadm5_auth_princ *princ,
        const krb5rs_kadm5_auth_policy *pol,
        krb5rs_kadm5_auth_restrictions **rs)
{
    krb5rs_kadm5_auth_restrictions *r;

    if (op != KADM5_AUTH_OP_ADDPRINC || strncmp(p1, "lim", 3) != 0)
        return NO_HANDLE;
    r = calloc(1, sizeof(*r));
    if (r == NULL)
        return DENY;
    r->mask = KADM5_MAX_LIFE;
    r->max_life = 3600;
    *rs = r;
    return 0;
}

static void
limiter_free(void *data, krb5rs_kadm5_auth_restrictions *rs)
{
    free(rs);
}

static int
skipped_init(const char *acl_file, void **data)
{
    return NO_HANDLE;
}

int
kadm5_auth_welcomer_initvt(int maj, int min, krb5rs_kadm5_auth_vtable *vt)
{
    vt->name = "welcomer";
    vt->authorize = welcomer;
    vt->end = welcomer_end;
    return 0;
}

int
kadm5_auth_bouncer_initvt(int maj, int min, krb5rs_kadm5_auth_vtable *vt)
{
    vt->name = "bouncer";
    vt->authorize = bouncer;
    return 0;
}

int
kadm5_auth_limiter_initvt(int maj, int min, krb5rs_kadm5_auth_vtable *vt)
{
    vt->name = "limiter";
    vt->authorize = limiter;
    vt->free_restrictions = limiter_free;
    return 0;
}

int
kadm5_auth_skipped_initvt(int maj, int min, krb5rs_kadm5_auth_vtable *vt)
{
    vt->name = "skipped";
    vt->init = skipped_init;
    vt->authorize = welcomer;
    return 0;
}
