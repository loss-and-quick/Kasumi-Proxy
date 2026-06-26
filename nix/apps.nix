# `nix run .#<app>` entry points — thin wrappers that put the right tools on PATH
# and exec the scripts/ helpers against the caller's working tree (PROJECT_ROOT,
# not the read-only store copy).
{
  pkgs,
  self,
  toolchain,
}:
let
  inherit (toolchain) rustAndroid ndkRoot;
  binPath = pkgs.lib.makeBinPath;
in
{
  # Cross-build the Rust daemon (kasumi-proxy) into module/bin/<abi>/. Needs the
  # android-target toolchain (rustAndroid) + cargo-ndk + NDK_ROOT.
  build-daemon-android = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "build-daemon-android" ''
        export PATH=${
          binPath [
            rustAndroid
            pkgs.cargo-ndk
            pkgs.coreutils
          ]
        }:$PATH
        export NDK_ROOT="${ndkRoot}"
        export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
        exec ${pkgs.bash}/bin/bash "${self}/scripts/build-daemon-android.sh" "$@"
      ''
    );
  };

  # Download the core binaries. `fetch-cores android` → module/bin/<abi>/;
  # `fetch-cores desktop [triple]` → src-tauri/binaries/.
  fetch-cores = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "fetch-cores" ''
        export PATH=${
          binPath [
            pkgs.curl
            pkgs.jq
            pkgs.unzip
            pkgs.gnutar
            pkgs.gzip
            pkgs.go
            pkgs.coreutils
          ]
        }:$PATH
        export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
        exec ${pkgs.bash}/bin/bash "${self}/scripts/fetch-cores.sh" "$@"
      ''
    );
  };

  # Build the React app into module/webroot/.
  build-webroot = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "build-webroot" ''
        export PATH=${
          binPath [
            pkgs.bun
            pkgs.coreutils
          ]
        }:$PATH
        export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
        exec ${pkgs.bash}/bin/bash "${self}/scripts/build-webroot.sh" "$@"
      ''
    );
  };

  # Assemble the installable Android module zip (geodat2srs + cores + the
  # cross-built Rust daemon + webroot). Cores + geodat2srs are fetched/built by
  # scripts/fetch-cores.sh (needs Go), the daemon by cargo-ndk.
  package-release = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "package-release" ''
        export PATH=${
          binPath [
            rustAndroid
            pkgs.cargo-ndk
            pkgs.go
            pkgs.curl
            pkgs.jq
            pkgs.unzip
            pkgs.gnutar
            pkgs.gzip
            pkgs.zip
            pkgs.bun
            pkgs.coreutils
          ]
        }:$PATH
        export NDK_ROOT="${ndkRoot}"
        export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
        exec ${pkgs.bash}/bin/bash "${self}/scripts/package-release.sh" "$@"
      ''
    );
  };
}
