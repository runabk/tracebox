Name:           runa-tracebox
Version:        0.5.0~td1.6
Release:        1
Summary:        -

Group:          Applications/Internet
License:        GPL
URL:            http://www.tracebox.org
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  autoconf, automake, libtool, libpcap-devel, libdnet-devel, lua-devel, python-devel, git, fakeroot
Requires:       libpcap, libdnet, lua, scapy, pcapy

%description


%prep
%setup -q


%build
rm -rf noinst/libcrafter
rm -rf tests/tools/click
git clone --depth=1 https://github.com/gdetal/libcrafter.git noinst/libcrafter
git clone --depth=1 https://github.com/bhesmans/click.git tests/tools/click
autoreconf -if


%configure --enable-tests --disable-scripts --prefix=/usr
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/luatracebox
%{_bindir}/tracebox
%{_datadir}/man/man1/tracebox.1.gz
%{_datadir}/tracebox/*.tbx


%changelog
