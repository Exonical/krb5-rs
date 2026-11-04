/*
 * Port of MIT krb5 1.22 plugins/pwqual/test/main.c to krb5-rs's
 * pwqual_plugin.h: "combo" refuses a pair of dictionary words, and "dyn1",
 * "dyn2" and "dyn3" only have names.
 */
#include <krb5-rs/pwqual_plugin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    char **words;
    char *block;
} combo_dict;

static int
combo_open(const char *dict_file, void **data)
{
    combo_dict *d = calloc(1, sizeof(*d));
    FILE *f;
    long len;
    size_t count = 0, i;
    char *p;

    if (d == NULL)
        return 12;
    *data = d;
    if (dict_file == NULL || (f = fopen(dict_file, "r")) == NULL)
        return 0;
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    rewind(f);
    d->block = calloc(1, len + 1);
    if (d->block == NULL || fread(d->block, 1, len, f) != (size_t)len) {
        fclose(f);
        return 5;
    }
    fclose(f);
    for (p = d->block; (p = strchr(p, '\n')) != NULL; p++) {
        *p = '\0';
        count++;
    }
    d->words = calloc(count + 1, sizeof(char *));
    if (d->words == NULL)
        return 12;
    for (i = 0, p = d->block; i < count; i++) {
        d->words[i] = p;
        p += strlen(p) + 1;
    }
    return 0;
}

static int
combo_check(void *data, const char *password, const char *policy,
            const char *princ, char *msg, size_t msg_len)
{
    combo_dict *d = data;
    char **w1, **w2;

    (void)policy;
    (void)princ;
    if (d->words == NULL)
        return 0;
    for (w1 = d->words; *w1 != NULL; w1++) {
        if (strncasecmp(password, *w1, strlen(*w1)) != 0)
            continue;
        for (w2 = d->words; *w2 != NULL; w2++) {
            if (strcasecmp(password + strlen(*w1), *w2) == 0) {
                snprintf(msg, msg_len,
                         "Password may not be a pair of dictionary words");
                return KRB5_RS_KADM5_PASS_Q_DICT;
            }
        }
    }
    return 0;
}

static void
combo_close(void *data)
{
    combo_dict *d = data;

    free(d->words);
    free(d->block);
    free(d);
}

int
pwqual_combo_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)min_ver;
    if (maj_ver != 1)
        return -1765328160; /* KRB5_PLUGIN_VER_NOTSUPP */
    vt->name = "combo";
    vt->open = combo_open;
    vt->check = combo_check;
    vt->close = combo_close;
    return 0;
}

int
pwqual_dyn1_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)maj_ver;
    (void)min_ver;
    vt->name = "dyn1";
    return 0;
}

int
pwqual_dyn2_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)maj_ver;
    (void)min_ver;
    vt->name = "dyn2";
    return 0;
}

int
pwqual_dyn3_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)maj_ver;
    (void)min_ver;
    vt->name = "dyn3";
    return 0;
}

/* Fails to initialize its vtable, which skips it. */
int
pwqual_novt_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)maj_ver;
    (void)min_ver;
    (void)vt;
    return -1765328160;
}

/* Fails to open, which is fatal. */
static int
fail_open(const char *dict_file, void **data)
{
    (void)dict_file;
    (void)data;
    return 5;
}

int
pwqual_badopen_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt)
{
    (void)maj_ver;
    (void)min_ver;
    vt->name = "badopen";
    vt->open = fail_open;
    return 0;
}
