/*
 * krb5-rs password quality module interface.
 *
 * Modules are configured as in MIT krb5 1.22:
 *
 *     [plugins]
 *         pwqual = {
 *             module = name:path/to/module.so
 *             enable_only = name
 *             disable = princ
 *         }
 *
 * and export pwqual_<name>_initvt, which krb5-rs-kadmind and krb5-rs-kdb
 * call with major version 1 and minor version 0.  The vtable differs from
 * MIT's pwqual_plugin.h: the principal is an unparsed string, no
 * krb5_context or languages are given, and the error message is written to
 * msg instead of krb5_set_error_message.
 *
 * Module callbacks never run at once.
 */
#ifndef KRB5_RS_PWQUAL_PLUGIN_H
#define KRB5_RS_PWQUAL_PLUGIN_H

#include <stddef.h>

#define KRB5_RS_KADM5_PASS_Q_TOOSHORT 43787542L
#define KRB5_RS_KADM5_PASS_Q_CLASS 43787543L
#define KRB5_RS_KADM5_PASS_Q_DICT 43787544L
#define KRB5_RS_KADM5_PASS_Q_GENERIC 43787577L

typedef struct krb5_rs_pwqual_vtable {
    /* Mandatory module name. */
    const char *name;
    /* Open the module with the realm's dict_file (or NULL).  An error stops
     * the program, as in MIT. */
    int (*open)(const char *dict_file, void **data);
    /* Return 0 to accept password for princ (with policy, or NULL), or a
     * kadm5 or com_err code to refuse it, optionally writing a message of
     * at most msg_len bytes (NUL included) to msg. */
    int (*check)(void *data, const char *password, const char *policy,
                 const char *princ, char *msg, size_t msg_len);
    /* Release data. */
    void (*close)(void *data);
} krb5_rs_pwqual_vtable;

int pwqual_NAME_initvt(int maj_ver, int min_ver, krb5_rs_pwqual_vtable *vt);

#endif
