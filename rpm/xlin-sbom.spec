%global debug_package %{nil}
%global __os_install_post %{nil}

Name:           xlin-sbom
Version:        1.1.0
Release:        1%{?dist}
Summary:        XiLing SBOM generation tool
License:        Apache-2.0
URL:            https://www.linxsoftware.com
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  gzip
BuildRequires:  tar

Requires:       python3
Requires:       python3-pycdlib
Requires:       python3-tqdm
Requires:       python3-requests
Requires:       python3-beautifulsoup4
Requires:       python3-chardet
Requires:       python3-semantic_version
Requires:       python3-rpm
Requires:       python3-license-expression
Requires:       squashfs-tools
Requires:       openssl
Requires:       rpm
Requires:       zstd

# 可选能力：DEB 包/软件源扫描依赖 python-debian；源码许可证识别依赖
# scancode-toolkit。缺失时对应功能会记录告警并跳过，不影响其余扫描。
Recommends:     python3-debian
Recommends:     python3-zstandard
Suggests:       scancode-toolkit

%description
析灵 SBOM 生成工具用于扫描 ISO 镜像、Docker 镜像、RPM/DEB 软件包、
源码归档和软件源，并生成 Linx、SPDX 2.2/2.3/3.0 以及
GB/T 47020-2026（SBOMDF）格式的软件物料清单。

软件包不内置 Python 第三方依赖，统一使用系统提供的 python3 与
python3-* 模块。

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -d %{buildroot}%{_datadir}/%{name}
cp -a linx-xiling.py actions assist %{buildroot}%{_datadir}/%{name}/

find %{buildroot}%{_datadir}/%{name} -type d -name __pycache__ \
    -prune -exec rm -rf {} +

install -Dpm644 config/config.json %{buildroot}%{_sysconfdir}/%{name}/config.json
install -d %{buildroot}%{_datadir}/%{name}/config
ln -s ../../../../etc/%{name}/config.json \
    %{buildroot}%{_datadir}/%{name}/config/config.json

install -Dpm755 rpm/xlin-sbom.wrapper %{buildroot}%{_bindir}/xlin-sbom
ln -s xlin-sbom %{buildroot}%{_bindir}/linx-xiling

%files
%license LICENSE
%doc README.md README.en.md AUTHORS NOTICE
%config(noreplace) %{_sysconfdir}/%{name}/config.json
%{_bindir}/xlin-sbom
%{_bindir}/linx-xiling
%{_datadir}/%{name}/

%changelog
* Tue Nov 10 2026 yanbowen <yanbowen@uniontech.com> - 1.1.0-1
- Use distribution python3 and python3-* packages instead of bundled vendor
