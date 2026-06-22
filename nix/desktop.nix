# The desktop pipeline: the React UI (bun2nix), the crane-tauri app, and the
# GTK-wrapped `kasumi-desktop` binary with the cores + tray lib wired in.
{
  pkgs,
  root,
  crane-tauri,
  toolchain,
  version,
  cores,
}:
let
  inherit (toolchain) lib craneLib tauriLibs;

  # The React UI built into static assets. bun2nix reconstructs node_modules from
  # the generated bun.nix (one fixed-output fetch per package, no opaque tree
  # hash); its hook also patches the dep CLI shebangs. The vite build is then
  # offline and deterministic. Regenerate bun.nix with `bunx bun2nix` after
  # changing bun.lock.
  frontend = pkgs.stdenv.mkDerivation {
    pname = "kasumi-frontend";
    version = version.appVersion;
    src = lib.fileset.toSource {
      inherit root;
      fileset = lib.fileset.unions [
        (root + "/package.json")
        (root + "/bun.lock")
        (root + "/bun.nix")
        (root + "/frontend")
      ];
    };
    nativeBuildInputs = [
      pkgs.bun2nix.hook
      pkgs.nodejs_22
    ];
    bunDeps = pkgs.bun2nix.fetchBunDeps {
      bunNix = root + "/bun.nix";
    };
    buildPhase = ''
      ( cd frontend && bun run build )
    '';
    installPhase = ''
      cp -R frontend/dist $out
    '';
    dontFixup = true;
  };

  # crane-tauri assembles the Tauri 2 app: builds the Rust workspace with the
  # built `frontend` embedded, reusing a crane dependency cache. cargoRoot is the
  # workspace root because src-tauri depends on ../crates/* by path; the installed
  # binary is cargo's package name (kasumi-desktop).
  tauri = crane-tauri.lib.buildTauriApp { inherit pkgs craneLib; } {
    pname = "kasumi-proxy";
    version = version.appVersion;
    src = root;
    cargoRoot = root;
    binaryName = "kasumi-desktop";
    inherit frontend;
  };

  # crane-tauri leaves GTK/WebKit wrapping to the consumer (wrapping in the shared
  # inputs would perturb PKG_CONFIG_PATH and bust -sys fingerprints). webkit2gtk-4.1
  # is GTK3-based, so wrap with wrapGAppsHook3.
  kasumi-desktop = pkgs.stdenv.mkDerivation {
    pname = "kasumi-desktop";
    version = version.appVersion;
    dontUnpack = true;
    nativeBuildInputs = [
      pkgs.wrapGAppsHook3
      pkgs.gobject-introspection
      pkgs.patchelf
      pkgs.copyDesktopItems
    ];
    buildInputs = tauriLibs;
    # Point the app at the bundled cores by default (the desktop Platform reads
    # KASUMI_BIN_DIR); --set-default lets a dev still override it. KASUMI_IP_DIR
    # hands the elevated data-path an absolute `ip`: after the pkexec re-exec the
    # root instance inherits pkexec's scrubbed PATH, which on NixOS has no `ip`
    # (no /usr/sbin/ip), so a bare PATH lookup fails. elevate.rs forwards both vars
    # across the pkexec boundary.
    preFixup = ''
      gappsWrapperArgs+=(--set-default KASUMI_BIN_DIR "${cores.desktopCores}/bin")
      gappsWrapperArgs+=(--set-default KASUMI_IP_DIR "${pkgs.iproute2}/bin")
    '';
    installPhase = ''
      mkdir -p $out/bin
      cp ${tauri.app}/bin/kasumi-desktop $out/bin/kasumi-desktop
      # Launcher icon (the file basenames already encode their pixel size).
      install -Dm644 ${root + "/src-tauri/icons/32x32.png"} \
        $out/share/icons/hicolor/32x32/apps/kasumi-proxy.png
      install -Dm644 ${root + "/src-tauri/icons/128x128.png"} \
        $out/share/icons/hicolor/128x128/apps/kasumi-proxy.png
      install -Dm644 ${
        # The `@` in the source basename is illegal in a Nix store path name, so
        # rename it as it's imported (a bare `root + "/…@2x.png"` fails to realise).
        builtins.path {
          name = "kasumi-proxy-256.png";
          path = root + "/src-tauri/icons/128x128@2x.png";
        }
      } \
        $out/share/icons/hicolor/256x256/apps/kasumi-proxy.png
    '';
    # A `.desktop` entry so the app shows up in the launcher (copyDesktopItems hook).
    desktopItems = [
      (pkgs.makeDesktopItem {
        name = "kasumi-proxy";
        desktopName = "Kasumi Proxy";
        exec = "kasumi-desktop";
        icon = "kasumi-proxy";
        comment = "Transparent proxy (Xray-core / sing-box) with a native TUN and a React UI";
        categories = [ "Network" ];
        terminal = false;
      })
    ];
    # The tray icon dlopen's libayatana-appindicator at runtime (not linked). Bake
    # it into the binary's RUNPATH so dlopen finds it even after the app re-execs
    # as root via pkexec, which scrubs the environment (LD_LIBRARY_PATH would be
    # lost; RUNPATH survives). This MUST run in postFixup: the generic fixupPhase
    # runs `patchelf --shrink-rpath`, which would otherwise strip the path back out
    # (appindicator is dlopen'd, not a DT_NEEDED). wrapGAppsHook has by now renamed
    # the real ELF to .kasumi-desktop-wrapped.
    postFixup = ''
      patchelf --add-rpath ${lib.makeLibraryPath [ pkgs.libayatana-appindicator ]} \
        $out/bin/.kasumi-desktop-wrapped
    '';
    meta = {
      description = "Transparent proxy (Xray-core / sing-box) — Tauri 2 desktop app";
      homepage = "https://github.com/loss-and-quick/Kasumi-Proxy";
      license = lib.licenses.gpl3Plus;
      mainProgram = "kasumi-desktop";
      platforms = [ "x86_64-linux" ];
      maintainers = [ ];
    };
  };

  # `nix flake check` — clippy over the same source, reusing crane's dep cache.
  clippy = craneLib.cargoClippy (
    tauri.commonArgs
    // {
      cargoArtifacts = tauri.cargoArtifacts;
      cargoClippyExtraArgs = "--all-targets -- -D warnings";
      TAURI_CONFIG = tauri.tauriConfig;
    }
  );
in
{
  inherit
    frontend
    tauri
    kasumi-desktop
    clippy
    ;
}
