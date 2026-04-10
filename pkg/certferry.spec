Name:           certferry
Version:        %{_version}
Release:        1%{?dist}
Summary:        Distribute Let's Encrypt certificates across servers
License:        MIT
URL:            https://github.com/valentinobredemern/cert-ferry

%description
certferry fetches TLS certificates from remote servers and writes them
to the standard certbot directory structure. Designed for distributing
wildcard certificates to multiple servers.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/lib/systemd/system
cp %{_builddir}/certferry %{buildroot}/usr/bin/certferry
sed 's|%%CERTFERRY_EXE%%|/usr/bin/certferry|g' %{_builddir}/certferry-renew.service > %{buildroot}/usr/lib/systemd/system/certferry-renew.service
cp %{_builddir}/certferry-renew.timer %{buildroot}/usr/lib/systemd/system/certferry-renew.timer

%files
/usr/bin/certferry
/usr/lib/systemd/system/certferry-renew.service
/usr/lib/systemd/system/certferry-renew.timer
