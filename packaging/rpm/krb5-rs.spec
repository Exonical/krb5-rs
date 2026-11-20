# packaging/rpm/build.sh fills in @VERSION@ from Cargo.toml.
%global debug_package %{nil}
%{!?cargo: %global cargo cargo}

Name:           krb5-rs
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Pure Rust Kerberos V5, compatible with MIT krb5
License:        Apache-2.0
URL:            https://github.com/Exonical/krb5-rs
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros

%description
krb5-rs is a Rust implementation of Kerberos V5 that reads MIT krb5's
configuration and database files and speaks its protocols.

%package -n krb5-workstation-rs
Summary:        Kerberos 5 client programs (krb5-rs)
Conflicts:      krb5-workstation

%description -n krb5-workstation-rs
kinit, klist, kdestroy, kvno, kswitch, kpasswd, kadmin, ktutil, kcpytkt,
kdeltkt, k5srvutil and ksu from krb5-rs, under MIT krb5's names.

%package -n krb5-server-rs
Summary:        Kerberos 5 KDC, kadmind and database propagation (krb5-rs)
Conflicts:      krb5-server
%{?systemd_requires}

%description -n krb5-server-rs
krb5kdc, kadmind, kadmin.local, kdb5_util, kprop, kpropd and kproplog from krb5-rs, under
MIT krb5's names, with systemd units like RHEL's krb5-server.

%package -n krb5-server-ldap-rs
Summary:        LDAP database administration for the krb5-rs KDC
Requires:       krb5-server-rs = %{version}-%{release}
Conflicts:      krb5-server-ldap

%description -n krb5-server-ldap-rs
kdb5_ldap_util from krb5-rs. The KDC and kadmind in krb5-server-rs already
include the LDAP database module (db_library = kldap).

%package -n krb5-kdcproxy-rs
Summary:        Kerberos KDC proxy, MS-KKDCP over HTTPS (krb5-rs)
%{?systemd_requires}

%description -n krb5-kdcproxy-rs
kdcproxy from krb5-rs: an MS-KKDCP proxy that forwards Kerberos and kpasswd
requests sent over HTTPS to the realm's KDCs, configured like
python-kdcproxy through /etc/kdcproxy.conf.

%prep
%autosetup

%build
export KRB5RS_KDC_DIR=%{_localstatedir}/kerberos/krb5kdc
export KRB5RS_KDC_RUN_DIR=%{_rundir}/krb5kdc
%{cargo} build --release --locked -p krb5-rs-clients -p krb5-rs-kdc

%install
b=target/release
for p in kinit klist kdestroy kvno kswitch kpasswd kadmin ktutil kcpytkt kdeltkt k5srvutil ksu; do
    install -Dpm0755 $b/krb5-rs-$p %{buildroot}%{_bindir}/$p
done
install -Dpm0755 $b/krb5-rs-kdc %{buildroot}%{_sbindir}/krb5kdc
install -Dpm0755 $b/krb5-rs-kadmind %{buildroot}%{_sbindir}/kadmind
install -Dpm0755 $b/krb5-rs-kadmin-local %{buildroot}%{_sbindir}/kadmin.local
install -Dpm0755 $b/krb5-rs-kdb %{buildroot}%{_sbindir}/kdb5_util
install -Dpm0755 $b/krb5-rs-kprop %{buildroot}%{_sbindir}/kprop
install -Dpm0755 $b/krb5-rs-kpropd %{buildroot}%{_sbindir}/kpropd
install -Dpm0755 $b/krb5-rs-kproplog %{buildroot}%{_sbindir}/kproplog
install -Dpm0755 $b/krb5-rs-kdcproxy %{buildroot}%{_sbindir}/kdcproxy
install -Dpm0755 $b/krb5-rs-kdb5-ldap-util %{buildroot}%{_sbindir}/kdb5_ldap_util
# kadmind, kprop and kpropd run these helpers from their own directory.
ln -s kdb5_util %{buildroot}%{_sbindir}/krb5-rs-kdb
ln -s kprop %{buildroot}%{_sbindir}/krb5-rs-kprop

r=packaging/rpm
for u in krb5kdc kadmin kprop; do
    install -Dpm0644 $r/$u.service %{buildroot}%{_unitdir}/$u.service
    install -Dpm0644 $r/$u.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/$u
done
install -Dpm0644 $r/kdcproxy.service %{buildroot}%{_unitdir}/kdcproxy.service
install -Dpm0644 $r/kdcproxy.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/kdcproxy
install -Dpm0644 $r/kdcproxy.conf %{buildroot}%{_sysconfdir}/kdcproxy.conf
install -Dpm0644 $r/krb5-rs.tmpfiles %{buildroot}%{_tmpfilesdir}/krb5-rs.conf
install -d -m0700 %{buildroot}%{_localstatedir}/kerberos/krb5kdc
install -pm0600 $r/kdc.conf $r/kadm5.acl %{buildroot}%{_localstatedir}/kerberos/krb5kdc/

%post -n krb5-server-rs
%systemd_post krb5kdc.service kadmin.service kprop.service

%preun -n krb5-server-rs
%systemd_preun krb5kdc.service kadmin.service kprop.service

%postun -n krb5-server-rs
%systemd_postun_with_restart krb5kdc.service kadmin.service kprop.service

%post -n krb5-kdcproxy-rs
%systemd_post kdcproxy.service

%preun -n krb5-kdcproxy-rs
%systemd_preun kdcproxy.service

%postun -n krb5-kdcproxy-rs
%systemd_postun_with_restart kdcproxy.service

%files -n krb5-workstation-rs
%license LICENSE*
%{_bindir}/kinit
%{_bindir}/klist
%{_bindir}/kdestroy
%{_bindir}/kvno
%{_bindir}/kswitch
%{_bindir}/kpasswd
%{_bindir}/kadmin
%{_bindir}/ktutil
%{_bindir}/kcpytkt
%{_bindir}/kdeltkt
%{_bindir}/k5srvutil
%attr(4755,root,root) %{_bindir}/ksu

%files -n krb5-server-rs
%license LICENSE*
%{_sbindir}/krb5kdc
%{_sbindir}/kadmind
%{_sbindir}/kadmin.local
%{_sbindir}/kdb5_util
%{_sbindir}/kprop
%{_sbindir}/kpropd
%{_sbindir}/kproplog
%{_sbindir}/krb5-rs-kdb
%{_sbindir}/krb5-rs-kprop
%{_unitdir}/krb5kdc.service
%{_unitdir}/kadmin.service
%{_unitdir}/kprop.service
%config(noreplace) %{_sysconfdir}/sysconfig/krb5kdc
%config(noreplace) %{_sysconfdir}/sysconfig/kadmin
%config(noreplace) %{_sysconfdir}/sysconfig/kprop
%{_tmpfilesdir}/krb5-rs.conf
%dir %{_localstatedir}/kerberos
%dir %attr(0700,root,root) %{_localstatedir}/kerberos/krb5kdc
%config(noreplace) %{_localstatedir}/kerberos/krb5kdc/kdc.conf
%config(noreplace) %{_localstatedir}/kerberos/krb5kdc/kadm5.acl

%files -n krb5-server-ldap-rs
%{_sbindir}/kdb5_ldap_util

%files -n krb5-kdcproxy-rs
%license LICENSE*
%{_sbindir}/kdcproxy
%{_unitdir}/kdcproxy.service
%config(noreplace) %{_sysconfdir}/sysconfig/kdcproxy
%config(noreplace) %{_sysconfdir}/kdcproxy.conf
