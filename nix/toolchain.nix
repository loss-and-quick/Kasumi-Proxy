# Shared toolchains + library sets derived from `pkgs` (rust-overlay + bun2nix
# overlays applied in flake.nix). Returned attrset is threaded into the other
# nix/ modules.
{
  pkgs,
  crane,
}: let
  inherit (pkgs) lib;

  # The pinned toolchain is single-sourced from //rust-toolchain.toml (also read by
  # rustup for a bare `cargo`), so the version lives in exactly one place. Every
  # consumer below — the host dev-shell tools, the android cross-build, the crane
  # desktop build, `nix flake check` — derives from this single derivation; bump the
  # file to move them all. See that file for why the release is pinned exactly.
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

  # The pinned toolchain + the android std targets, for cargo-ndk daemon builds.
  rustAndroid = rustToolchain.override {
    targets = [
      "aarch64-linux-android"
      "x86_64-linux-android"
    ];
  };

  # Android SDK/NDK — for cross-building the Rust daemon (cargo-ndk) and
  # geodat2srs into the module, and (later) the Tauri Android target.
  androidComposition = pkgs.androidenv.composeAndroidPackages {
    includeNDK = true;
    ndkVersions = ["28.0.13004108"];
    platformVersions = ["35"];
    cmdLineToolsVersion = "12.0";
    platformToolsVersion = "36.0.2";
    buildToolsVersions = ["35.0.0"];
  };
  androidSdk = androidComposition.androidsdk;
  ndkRoot = "${androidSdk}/libexec/android-sdk/ndk/28.0.13004108";
  ndkHost =
    if pkgs.stdenv.isAarch64
    then "linux-aarch64"
    else "linux-x86_64";

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

  # `rustToolchain` carries rustc/cargo/rustfmt/clippy for the host triple (the
  # default profile); cargo-tauri / cargo-ndk are separate cargo subcommands.
  # Deriving from `rustToolchain` keeps the dev shell on the pinned toolchain.
  rustTools = [
    rustToolchain
    pkgs.cargo-tauri
    pkgs.cargo-ndk
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
in {
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
