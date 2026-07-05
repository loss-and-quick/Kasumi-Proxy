{self, ...}: {
  perSystem = {
    pkgs,
    lib,
    toolchain,
    ...
  }: let
    inherit (lib) getExe makeBinPath;
    inherit (toolchain) rustAndroid ndkRoot;
  in {
    apps = {
      # Cross-build the Rust daemon (kasumi-proxy) into module/bin/<abi>/. Needs the
      # android-target toolchain (rustAndroid) + cargo-ndk + NDK_ROOT.
      build-daemon-android = {
        type = "app";
        program = toString (
          pkgs.writeShellScript "build-daemon-android" ''
            export PATH=${
              makeBinPath [
                rustAndroid
                pkgs.cargo-ndk
                pkgs.coreutils
              ]
            }:$PATH
            export NDK_ROOT="${ndkRoot}"
            export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
            exec ${getExe pkgs.bash} "${self}/scripts/build-daemon-android.sh" "$@"
          ''
        );
      };

      # Download/build the binaries. `fetch-binaries android` → module/bin/<abi>/;
      # `fetch-binaries desktop [triple]` → src-tauri/binaries/.
      fetch-binaries = {
        type = "app";
        program = toString (
          pkgs.writeShellScript "fetch-binaries" ''
            export PATH=${
              makeBinPath [
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
            exec ${getExe pkgs.bash} "${self}/scripts/fetch-binaries.sh" "$@"
          ''
        );
      };

      # Build the React app into module/webroot/.
      build-webroot = {
        type = "app";
        program = toString (
          pkgs.writeShellScript "build-webroot" ''
            export PATH=${
              makeBinPath [
                pkgs.bun
                pkgs.coreutils
              ]
            }:$PATH
            export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
            exec ${getExe pkgs.bash} "${self}/scripts/build-webroot.sh" "$@"
          ''
        );
      };

      # Assemble the installable Android module zip (cores + geodat2srs + the
      # cross-built Rust daemon + webroot). The cores + geodat2srs are fetched/built by
      # scripts/fetch-binaries.sh (needs Go), the daemon by cargo-ndk.
      package-release = {
        type = "app";
        program = toString (
          pkgs.writeShellScript "package-release" ''
            export PATH=${
              makeBinPath [
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
            exec ${getExe pkgs.bash} "${self}/scripts/package-release.sh" "$@"
          ''
        );
      };
    };
  };
}
