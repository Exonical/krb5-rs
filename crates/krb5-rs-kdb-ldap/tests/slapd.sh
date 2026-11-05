#!/bin/sh
# Start a private OpenLDAP server with MIT's Kerberos schema for the kldap
# integration tests: slapd.sh <dir> <port>. Prints slapd's pid.
set -eu
dir=$1
port=$2
here=$(cd "$(dirname "$0")" && pwd)
schema=/etc/ldap/schema
moddir=/usr/lib/ldap
rm -rf "$dir"
mkdir -p "$dir/slapd.d" "$dir/db"
cat >"$dir/config.ldif" <<LDIF
dn: cn=config
objectClass: olcGlobal
cn: config
olcPidFile: $dir/slapd.pid

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: $moddir
olcModuleLoad: back_mdb

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

include: file://$schema/core.ldif
include: file://$schema/cosine.ldif
include: file://$schema/inetorgperson.ldif
include: file://$here/../schema/kerberos.openldap.ldif

dn: olcDatabase={-1}frontend,cn=config
objectClass: olcDatabaseConfig
objectClass: olcFrontendConfig
olcDatabase: {-1}frontend

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcAccess: {0}to * by * none

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcSuffix: dc=example,dc=com
olcRootDN: cn=admin,dc=example,dc=com
olcRootPW: secret
olcDbDirectory: $dir/db
olcDbIndex: objectClass eq
olcDbIndex: krbPrincipalName eq,pres,sub
olcAccess: {0}to * by * read
LDIF
slapadd -n0 -F "$dir/slapd.d" -l "$dir/config.ldif" 
cat >"$dir/base.ldif" <<LDIF
dn: dc=example,dc=com
objectClass: dcObject
objectClass: organization
o: example
dc: example

dn: ou=people,dc=example,dc=com
objectClass: organizationalUnit
ou: people
LDIF
slapadd -n1 -F "$dir/slapd.d" -l "$dir/base.ldif" 
# Ubuntu's AppArmor profile for /usr/sbin/slapd denies paths outside
# /etc/ldap and /var/lib/ldap; a copy of the binary is not confined.
cp "$(command -v slapd)" "$dir/slapd"
"$dir/slapd" -F "$dir/slapd.d" -h "ldap://127.0.0.1:$port/" >/dev/null 2>&1
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s "$dir/slapd.pid" ] && break
    sleep 0.3
done
cat "$dir/slapd.pid"
