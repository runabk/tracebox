Name:           tracebox
Version:        0.1~td3.0
Release:        1%{?dist}
Summary:        -

Group:          Applications/Internet
License:        GPL
URL:            http://www.tracebox.org
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  libpcap-devel, libdnet-devel, lua-devel, python-devel
Requires:       libpcap, libdnet, lua, scapy, pcapy

%description


%prep
%setup -q


%build
autoreconf -if


%configure --disable-scripts --prefix=/usr
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
