# `nix run .#<app>` entry points — thin wrappers that put the right tools on PATH
# and exec the scripts/ helpers against the caller's working tree (PROJECT_ROOT,
# not the read-only store copy).
{
  pkgs,
  self,
  toolchain,
}:
let
  inherit (toolchain) rustAndroid ndkRoot ndkHost;
  binPath = pkgs.lib.makeBinPath;
in
{
  # Build geodat2srs for Android targets (into module/bin/<abi>/).
  build-geodat2srs = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "build-geodat2srs" ''
        set -euo pipefail
        SRC="$HOME/geodat2srs"
        BIN="''${PROJECT_ROOT:-$PWD}/module/bin"
        if [ ! -d "$SRC" ]; then
          ${pkgs.git}/bin/git clone https://github.com/loss-and-quick/geodat2srs.git "$SRC"
        fi
        export PATH=${
          binPath [
            pkgs.go
            pkgs.git
            pkgs.coreutils
          ]
        }:$PATH
        NDK="${ndkRoot}"
        CC_ARM64="$NDK/toolchains/llvm/prebuilt/${ndkHost}/bin/aarch64-linux-android35-clang"
        CC_AMD64="$NDK/toolchains/llvm/prebuilt/${ndkHost}/bin/x86_64-linux-android35-clang"
        echo "→ Building geodat2srs android/arm64"
        cd "$SRC" && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$CC_ARM64" go build -o "$BIN/arm64-v8a/geodat2srs" .
        echo "→ Building geodat2srs android/amd64"
        cd "$SRC" && CGO_ENABLED=1 GOOS=android GOARCH=amd64 CC="$CC_AMD64" go build -o "$BIN/x86_64/geodat2srs" .
        chmod 755 "$BIN/arm64-v8a/geodat2srs" "$BIN/x86_64/geodat2srs"
      ''
    );
  };

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

  # Download the Android core binaries into module/bin/<abi>/.
  fetch-cores-android = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "fetch-cores-android" ''
        export PATH=${
          binPath [
            pkgs.curl
            pkgs.unzip
            pkgs.coreutils
          ]
        }:$PATH
        export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
        exec ${pkgs.bash}/bin/bash "${self}/scripts/fetch-cores-android.sh" "$@"
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
  # cross-built Rust daemon + webroot). The daemon step needs the android-target
  # toolchain + cargo-ndk, same as build-daemon-android.
  package-release = {
    type = "app";
    program = toString (
      pkgs.writeShellScript "package-release" ''
        export PATH=${
          binPath [
            rustAndroid
            pkgs.cargo-ndk
            pkgs.go
            pkgs.git
            pkgs.curl
            pkgs.unzip
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
