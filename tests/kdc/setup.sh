#!/bin/bash
set -euo pipefail
if [[ "${DEBUG_KDC_SETUP:-0}" == "1" ]]; then
    set -x
fi

# Allow overriding credentials via env vars so secrets don't appear in ps output.
# The default values below are for local testing only and MUST NOT be reused outside tests.
MASTER_KEY="${KDC_MASTER_KEY:-masterkey}"
TESTUSER1_PASSWORD="${KDC_TESTUSER1_PASSWORD:-testpassword}"
TESTUSER2_PASSWORD="${KDC_TESTUSER2_PASSWORD:-password2}"

# MIT krb5 is built into the image (tests/kdc/Dockerfile).
mkdir -p /etc/krb5kdc /var/lib/krb5kdc

# Write config files (overwrite the defaults created by package install)
cat > /etc/krb5.conf <<'CONF'
[libdefaults]
    default_realm = TEST.REALM
    forwardable = true
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    TEST.REALM = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1:749
    }
    OTHER.REALM = {
        kdc = kdc-other:88
    }
[domain_realm]
    .other.realm = OTHER.REALM
    other.realm = OTHER.REALM
CONF

cat > /etc/krb5kdc/kdc.conf <<'CONF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    TEST.REALM = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = /var/lib/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        max_life = 24h
        max_renewable_life = 7d
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        default_principal_flags = +preauth
        pkinit_identity = FILE:/pki/kdc-test-realm.pem,/pki/kdc-key.pem
        pkinit_anchors = FILE:/pki/ca.pem
    }
CONF

# A second KDC process on the same database that requires PKINIT freshness
# tokens (RFC 8070), on port 8888 (published as 10190).
sed -e 's/kdc_ports = 88$/kdc_ports = 8888/' \
    -e 's/kdc_tcp_ports = 88$/kdc_tcp_ports = 8888/' /etc/krb5kdc/kdc.conf | \
    awk '{ print } /pkinit_anchors/ { print "        pkinit_require_freshness = true" }' \
    > /etc/krb5kdc/kdc-fresh.conf

# Create KDC database
mkdir -p /var/lib/krb5kdc
# -W reads password from stdin; kdb5_util prompts twice (enter + verify)
printf '%s\n%s\n' "$MASTER_KEY" "$MASTER_KEY" | kdb5_util create -s -r TEST.REALM -W

# Create test principals
printf '%s\n%s\n' "$TESTUSER1_PASSWORD" "$TESTUSER1_PASSWORD" | \
    kadmin.local -q "addprinc testuser@TEST.REALM"
printf '%s\n%s\n' "$TESTUSER2_PASSWORD" "$TESTUSER2_PASSWORD" | \
    kadmin.local -q "addprinc testuser2@TEST.REALM"
# Known password (not -randkey) so the Rust GSS acceptor can derive the
# service key with string-to-key; -norandkey keeps the keytab at kvno 1.
HTTP_PASSWORD="${KDC_HTTP_PASSWORD:-httpsecret}"
printf '%s\n%s\n' "$HTTP_PASSWORD" "$HTTP_PASSWORD" | \
    kadmin.local -q "addprinc HTTP/server.test.realm@TEST.REALM"
kadmin.local -q "ktadd -norandkey -k /etc/krb5.keytab HTTP/server.test.realm@TEST.REALM"
# RFC 8009 (aes-sha2) only principal — exercises etypes 19/20 end to end.
SHA2USER_PASSWORD="${KDC_SHA2USER_PASSWORD:-sha2pass}"
printf '%s\n%s\n' "$SHA2USER_PASSWORD" "$SHA2USER_PASSWORD" | \
    kadmin.local -q "addprinc -e aes256-cts-hmac-sha384-192:normal,aes128-cts-hmac-sha256-128:normal sha2user@TEST.REALM"

# Anonymous PKINIT (kinit -n) needs the anonymous principal.
kadmin.local -q "addprinc -randkey WELLKNOWN/ANONYMOUS@TEST.REALM"

# Cross-realm trust: both KDCs need both krbtgt principals with matching keys.
# TEST.REALM uses krbtgt/OTHER.REALM@TEST.REALM to issue cross-realm TGTs;
# OTHER.REALM uses the same key to verify them (and vice versa).
TRUST_PASSWORD="${KDC_TRUST_PASSWORD:-crosstrust}"
printf '%s\n%s\n' "$TRUST_PASSWORD" "$TRUST_PASSWORD" | \
    kadmin.local -q "addprinc krbtgt/OTHER.REALM@TEST.REALM"
kadmin.local -q "modprinc -requires_preauth krbtgt/OTHER.REALM@TEST.REALM"
printf '%s\n%s\n' "$TRUST_PASSWORD" "$TRUST_PASSWORD" | \
    kadmin.local -q "addprinc krbtgt/TEST.REALM@OTHER.REALM"
kadmin.local -q "modprinc -requires_preauth krbtgt/TEST.REALM@OTHER.REALM"

echo "KDC initialized. Starting..."

# Enable KDC logging
cat >> /etc/krb5.conf << 'LOGGING'

[logging]
    kdc = STDERR
    admin_server = STDERR
    default = STDERR
LOGGING

# MIT GSS-API oracle (python3-gssapi over libgssapi_krb5) for interop tests.
if [[ -f /gss_oracle.py ]]; then
    ORACLE_PASSWORD="$TESTUSER1_PASSWORD" python3 /gss_oracle.py &
fi

# Freshness-requiring KDC (same database, other port and kdc.conf).
KRB5_KDC_PROFILE=/etc/krb5kdc/kdc-fresh.conf krb5kdc -n &

# Start KDC in foreground
exec krb5kdc -n
