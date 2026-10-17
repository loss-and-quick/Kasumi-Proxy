Name:           kasumi-proxy
Version:        %{version}
Release:        1%{?dist}
Summary:        System-wide transparent proxy (Xray-core / sing-box)

License:        GPL-3.0-or-later
URL:            https://github.com/loss-and-quick/Kasumi-Proxy
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  tar
BuildRequires:  unzip
BuildRequires:  curl
BuildRequires:  jq
BuildRequires:  golang
BuildRequires:  pkgconfig(gtk+-3.0)
BuildRequires:  pkgconfig(webkit2gtk-4.1)
BuildRequires:  pkgconfig(ayatana-appindicator3-0.1)
BuildRequires:  pkgconfig(librsvg-2.0)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  libcap-devel

Requires:       gtk3
Requires:       webkit2gtk4.1
Requires:       libayatana-appindicator-gtk3
Requires:       libcap

# Tauri produces bundled binaries that include prebuilt proxy engines (sing-box, xray, etc.)
%global _missing_build_ids_terminate_build 0
%global debug_package %{nil}

%description
Kasumi Proxy routes all traffic through Xray-core or sing-box with a native
TUN and policy routing, managed from a clean React UI.

%prep
%autosetup -n %{name}-%{version}

%build
# 1. Install or configure Rust toolchain if not available in chroot
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.95.0
    source "$HOME/.cargo/env"
fi

# 2. Install bun if not available
if ! command -v bun >/dev/null 2>&1; then
    curl -fsSL https://bun.sh/install | bash
    export PATH="$HOME/.bun/bin:$PATH"
fi

# 3. Build frontend
bun install --frozen-lockfile
(cd frontend && bun run build)

# 4. Fetch desktop cores and binaries
scripts/fetch-binaries.sh desktop x86_64-unknown-linux-gnu

# 5. Build binaries via Cargo
cargo build --release -p kasumi-desktop --bin kasumi-desktop --bin kasumi-helper

%install
rm -rf %{buildroot}

mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/%{name}
mkdir -p %{buildroot}%{_datadir}/applications
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/32x32/apps
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/128x128/apps
mkdir -p %{buildroot}%{_datadir}/icons/hicolor/256x256@2/apps

# Install kasumi binaries
install -p -m 0755 target/release/kasumi-desktop %{buildroot}%{_bindir}/kasumi-desktop
install -p -m 0755 target/release/kasumi-helper %{buildroot}%{_bindir}/kasumi-helper

# Install external core sidecars
install -p -m 0755 src-tauri/binaries/xray-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/xray
install -p -m 0755 src-tauri/binaries/sing-box-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/sing-box
install -p -m 0755 src-tauri/binaries/tun2socks-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/tun2socks
install -p -m 0755 src-tauri/binaries/hev-socks5-tunnel-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/hev-socks5-tunnel
install -p -m 0755 src-tauri/binaries/geodat2srs-x86_64-unknown-linux-gnu %{buildroot}%{_bindir}/geodat2srs

# Install libcronet.so
if [ -f src-tauri/binaries/libcronet.so ]; then
    install -p -m 0755 src-tauri/binaries/libcronet.so %{buildroot}%{_libdir}/%{name}/libcronet.so
fi

# Install desktop entry
cat << 'EOF' > %{buildroot}%{_datadir}/applications/kasumi-proxy.desktop
[Desktop Entry]
Categories=Utility;Network;
Comment=System-wide transparent proxy (Xray-core / sing-box).
Exec=kasumi-desktop
StartupWMClass=kasumi-desktop
Icon=kasumi-desktop
Name=Kasumi Proxy
Terminal=false
Type=Application
EOF

# Install icons
install -p -m 0644 src-tauri/icons/32x32.png %{buildroot}%{_datadir}/icons/hicolor/32x32/apps/kasumi-desktop.png
install -p -m 0644 src-tauri/icons/128x128.png %{buildroot}%{_datadir}/icons/hicolor/128x128/apps/kasumi-desktop.png
install -p -m 0644 src-tauri/icons/128x128@2x.png %{buildroot}%{_datadir}/icons/hicolor/256x256@2/apps/kasumi-desktop.png

%post
# Grant network & routing capabilities to kasumi-helper so it runs without pkexec
caps="cap_net_admin,cap_net_raw,cap_chown,cap_dac_override+ep"
if command -v setcap >/dev/null 2>&1; then
    setcap "$caps" %{_bindir}/kasumi-helper || true
fi

%files
%{_bindir}/kasumi-desktop
%{_bindir}/kasumi-helper
%{_bindir}/xray
%{_bindir}/sing-box
%{_bindir}/tun2socks
%{_bindir}/hev-socks5-tunnel
%{_bindir}/geodat2srs
%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libcronet.so
%{_datadir}/applications/kasumi-proxy.desktop
%{_datadir}/icons/hicolor/32x32/apps/kasumi-desktop.png
%{_datadir}/icons/hicolor/128x128/apps/kasumi-desktop.png
%{_datadir}/icons/hicolor/256x256@2/apps/kasumi-desktop.png

%changelog
* Sun Oct 18 2026 Kasumi Team <maintainers@kasumi.local>
- Initial Fedora Copr packaging
