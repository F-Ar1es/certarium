Name: certarium
Version: 0.1.0
Release: 1%{?dist}
Summary: Local RSA and Chinese-commercial-cryptography certificate laboratory
License: AGPL-3.0-only
URL: https://github.com/F-Ar1es/certarium
BuildArch: x86_64
Source0: rootfs
Requires(pre): shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Certarium is a loopback-only private PKI workbench for issuing, revoking, and
testing RSA and TLCP certificates with CRL and OCSP support.

%prep

%build

%install
mkdir -p %{buildroot}
cp -a %{_sourcedir}/rootfs/. %{buildroot}/
mkdir -p %{buildroot}/usr/share/certarium
mv %{buildroot}/etc/certarium/certarium.env %{buildroot}/usr/share/certarium/certarium.env.default

%pre
getent group certarium >/dev/null || groupadd -r certarium
getent passwd certarium >/dev/null || useradd -r -g certarium -d /var/lib/certarium -s /sbin/nologin -c 'Certarium service account' certarium
exit 0

%post
if [ ! -e /etc/certarium/certarium.env ]; then
    /usr/bin/install -m 0644 /usr/share/certarium/certarium.env.default /etc/certarium/certarium.env
fi
if [ -d /run/systemd/system ] && [ -x /bin/systemctl ]; then
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
    /bin/systemctl enable --now certarium.service >/dev/null 2>&1 || :
fi
exit 0

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ] && [ -x /bin/systemctl ]; then
    /bin/systemctl disable --now certarium.service >/dev/null 2>&1 || :
fi
exit 0

%postun
if [ -d /run/systemd/system ] && [ -x /bin/systemctl ]; then
    /bin/systemctl daemon-reload >/dev/null 2>&1 || :
fi
exit 0

%files
%license /usr/share/doc/certarium/LICENSE
%doc /usr/share/doc/certarium/NOTICE
%doc /usr/share/doc/certarium/THIRD_PARTY_NOTICES.md
%doc /usr/share/doc/certarium/COMMERCIAL_LICENSE.md
%doc /usr/share/doc/certarium/Tongsuo-LICENSE.txt
%doc /usr/share/doc/certarium/BUILD-MANIFEST.txt
/usr/bin/certarium
/opt/certarium/bin/openssl
/opt/certarium/lib/ossl-modules
/usr/lib/systemd/system/certarium.service
%dir /etc/certarium
/usr/share/certarium/certarium.env.default
%attr(0700,certarium,certarium) %dir /var/lib/certarium

%changelog
* Mon Aug 03 2026 Carl Flynn <noreply@example.invalid> - 0.1.0-1
- Initial experimental release
