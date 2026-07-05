{
  self,
  crane-tauri,
  ...
}: {
  perSystem = {
    pkgs,
    toolchain,
    version,
    binaries,
    ...
  }: let
    inherit (toolchain) lib craneLib tauriLibs baseNative;
    frontend = pkgs.stdenv.mkDerivation {
      pname = "kasumi-frontend";
      version = version.appVersion;
      src = ../.;
      nativeBuildInputs = with pkgs; [
        bun2nix.hook
        nodejs_22
      ];
      bunDeps = pkgs.bun2nix.fetchBunDeps {
        bunNix = self + "/bun.nix";
      };
      buildPhase = ''
        ( cd frontend && bun run build )
      '';
      installPhase = ''
        cp -R frontend/dist $out
      '';
      dontFixup = true;
    };
    tauriDrv = crane-tauri.lib.buildTauriApp {inherit pkgs craneLib;} {
      pname = "kasumi-proxy";
      version = version.appVersion;
      src = ../.;
      cargoRoot = ../.;
      binaryName = "kasumi-desktop";
      inherit frontend;
      # src-tauri/tauri.conf.json pins version to a "0.0.0" placeholder; override
      # it with the real appVersion so the built app reports the right version.
      extraTauriConfig = {
        version = version.appVersion;
      };
    };
    clippyArtifacts = craneLib.buildDepsOnly {
      pname = "kasumi-proxy-deps";
      version = version.appVersion;
      src = ../.;
      cargoRoot = ../.;
      nativeBuildInputs = baseNative;
      buildInputs = tauriLibs;
    };
  in {
    packages = rec {
      # The React UI built into static assets. bun2nix reconstructs node_modules from
      # the generated bun.nix (one fixed-output fetch per package, no opaque tree
      # hash); its hook also patches the dep CLI shebangs. The vite build is then
      # offline and deterministic. Regenerate bun.nix with `bunx bun2nix` after
      # changing bun.lock.
      inherit frontend;

      # crane-tauri assembles the Tauri 2 app: builds the Rust workspace with the
      # built `frontend` embedded, reusing a crane dependency cache. cargoRoot is the
      # workspace root because src-tauri depends on ../crates/* by path; the installed
      # binary is cargo's package name (kasumi-desktop).
      tauri = tauriDrv.app;

      # The privileged data-path helper is a second bin in the same crate. crane-tauri
      # installs only the app, so build the helper separately — reusing the dependency
      # cache + the tauri build env. Wrap it so iproute2 is on its PATH: the helper
      # shells out to `ip`, and pkexec scrubs the env + installs a minimal PATH that on
      # NixOS has no `ip`. The wrapper restores PATH after pkexec, so the code just
      # calls `ip` with no environment plumbing.
      helper-unwrapped = craneLib.buildPackage (
        tauriDrv.commonArgs
        // {
          pname = "kasumi-helper";
          inherit (tauriDrv) cargoArtifacts;
          cargoExtraArgs = "--bin kasumi-helper";
          TAURI_CONFIG = tauriDrv.tauriConfig;
          doCheck = false;
        }
      );
      helper =
        pkgs.runCommand "kasumi-helper"
        {
          nativeBuildInputs = [pkgs.makeBinaryWrapper];
        }
        ''
          mkdir -p $out/bin
          makeWrapper ${helper-unwrapped}/bin/kasumi-helper $out/bin/kasumi-helper \
            --prefix PATH : ${lib.makeBinPath [pkgs.iproute2]}
        '';

      # crane-tauri leaves GTK/WebKit wrapping to the consumer (wrapping in the shared
      # inputs would perturb PKG_CONFIG_PATH and bust -sys fingerprints). webkit2gtk-4.1
      # is GTK3-based, so wrap with wrapGAppsHook3.
      kasumi-desktop = pkgs.stdenv.mkDerivation {
        pname = "kasumi-desktop";
        version = version.appVersion;
        dontUnpack = true;
        nativeBuildInputs = with pkgs; [
          wrapGAppsHook3
          gobject-introspection
          patchelf
          copyDesktopItems
        ];
        buildInputs = tauriLibs;
        # Point the unprivileged GUI at the bundled binaries (it reads KASUMI_BIN_DIR
        # and forwards it to the root helper it spawns; --set-default lets a dev
        # override). Put iproute2 on PATH too: the GUI itself runs `ip monitor route`
        # for the uplink watch, and on NixOS there is no /usr/sbin/ip.
        preFixup = ''
          gappsWrapperArgs+=(--set-default KASUMI_BIN_DIR "${binaries.desktopBinaries}/bin")
          gappsWrapperArgs+=(--prefix PATH : "${lib.makeBinPath [pkgs.iproute2]}")
        '';
        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin
          cp ${tauri}/bin/kasumi-desktop $out/bin/kasumi-desktop
          # The GUI spawns this sibling for the data-path (privilege separation). The
          # NixOS module wraps it in a `security.wrappers.kasumi-helper` cap-set entry the
          # GUI execs directly; off NixOS it is granted caps via setcap or run via pkexec.
          cp ${helper}/bin/kasumi-helper $out/bin/kasumi-helper
          # Launcher icon (the file basenames already encode their pixel size).
          install -Dm644 ${self + "/src-tauri/icons/32x32.png"} \
            $out/share/icons/hicolor/32x32/apps/kasumi-proxy.png
          install -Dm644 ${self + "/src-tauri/icons/128x128.png"} \
            $out/share/icons/hicolor/128x128/apps/kasumi-proxy.png
          install -Dm644 ${
            # The `@` in the source basename is illegal in a Nix path literal, so
            # keep this one as a string-like flake path and rename it as it's imported.
            builtins.path {
              name = "kasumi-proxy-256.png";
              path = self + "/src-tauri/icons/128x128@2x.png";
            }
          } \
            $out/share/icons/hicolor/256x256/apps/kasumi-proxy.png
          runHook postInstall
        '';
        # A `.desktop` entry so the app shows up in the launcher (copyDesktopItems hook).
        desktopItems = [
          (pkgs.makeDesktopItem {
            name = "kasumi-proxy";
            desktopName = "Kasumi Proxy";
            exec = "kasumi-desktop";
            icon = "kasumi-proxy";
            comment = "Transparent proxy (Xray-core / sing-box) with a native TUN and a React UI";
            categories = ["Network"];
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
          patchelf --add-rpath ${lib.makeLibraryPath [pkgs.libayatana-appindicator]} \
            $out/bin/.kasumi-desktop-wrapped
        '';
        meta = {
          description = "Transparent proxy (Xray-core / sing-box) — Tauri 2 desktop app";
          homepage = "https://github.com/loss-and-quick/Kasumi-Proxy";
          license = lib.licenses.gpl3Plus;
          mainProgram = "kasumi-desktop";
          platforms = ["x86_64-linux"];
          maintainers = [];
        };
      };
    };

    # `nix flake check` — clippy over the same source, reusing crane's dep cache.
    checks = {
      clippy = craneLib.cargoClippy (
        {
          pname = "kasumi-proxy";
          src = self;
          cargoRoot = self;
          nativeBuildInputs = baseNative;
          buildInputs = tauriLibs;
        }
        // {
          cargoArtifacts = clippyArtifacts;
          cargoClippyExtraArgs = "--all-targets -- -D warnings";
          TAURI_CONFIG = tauriDrv.tauriConfig;
        }
      );
    };
  };
}
