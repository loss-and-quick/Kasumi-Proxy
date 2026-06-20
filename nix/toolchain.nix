# Shared toolchains + library sets derived from `pkgs` (rust-overlay + bun2nix
# overlays applied in flake.nix). Returned attrset is threaded into the other
# nix/ modules.
{ pkgs, crane }:
let
  lib = pkgs.lib;

  # Host toolchain + the android std targets, for cargo-ndk daemon builds.
  rustAndroid = pkgs.rust-bin.stable.latest.default.override {
    targets = [
      "aarch64-linux-android"
      "x86_64-linux-android"
    ];
  };

  # Android SDK/NDK — for cross-building the Rust daemon (cargo-ndk) and
  # geodat2srs into the module, and (later) the Tauri Android target.
  androidComposition = pkgs.androidenv.composeAndroidPackages {
    includeNDK = true;
    ndkVersions = [ "28.0.13004108" ];
    platformVersions = [ "35" ];
    cmdLineToolsVersion = "12.0";
    platformToolsVersion = "36.0.2";
    buildToolsVersions = [ "35.0.0" ];
  };
  androidSdk = androidComposition.androidsdk;
  ndkRoot = "${androidSdk}/libexec/android-sdk/ndk/28.0.13004108";
  ndkHost = if pkgs.stdenv.isAarch64 then "linux-aarch64" else "linux-x86_64";

  # System libraries a Tauri 2 app links against on Linux (webkit2gtk-4.1).
  # libayatana-appindicator is dlopen'd at runtime by the tray icon (the
  # tray-icon feature) — it must be reachable or the app aborts on start with
  # "Failed to load ayatana-appindicator3".
  tauriLibs = with pkgs; [
    glib
    gtk3
    cairo
    gdk-pixbuf
    pango
    harfbuzz
    at-spi2-atk
    atkmm
    librsvg
    libsoup_3
    webkitgtk_4_1
    libayatana-appindicator
    openssl
  ];

  rustTools = with pkgs; [
    rustc
    cargo
    clippy
    rustfmt
    cargo-tauri
    cargo-ndk
  ];

  nodeTools = with pkgs; [
    bun
    nodejs_22
  ];

  cliTools = with pkgs; [
    curl
    unzip
    zip
    gnutar
    gzip
    jq
    shellcheck
    git
    go
    cmake
    ninja
  ];

  # pkg-config + wrapGAppsHook4 wire GTK/WebKitGTK so the Tauri app links and
  # (when launched) finds its GSettings schemas / GIO modules.
  baseNative =
    (with pkgs; [
      pkg-config
      wrapGAppsHook4
      gobject-introspection
    ])
    ++ rustTools
    ++ nodeTools
    ++ cliTools;

  baseHook = ''
    export XDG_DATA_DIRS="${pkgs.gtk3}/share:${pkgs.gsettings-desktop-schemas}/share/gsettings-schemas/${pkgs.gsettings-desktop-schemas.name}:''${XDG_DATA_DIRS:-/usr/share}"
    export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
  '';
in
{
  inherit
    lib
    rustAndroid
    androidSdk
    ndkRoot
    ndkHost
    tauriLibs
    baseNative
    baseHook
    ;
  craneLib = crane.mkLib pkgs;
}
