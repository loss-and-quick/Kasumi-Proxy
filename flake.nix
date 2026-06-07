{
  description = "Kasumi Proxy — Magisk transparent proxy module (Xray-core / sing-box) with a React control center";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          config.android_sdk.accept_license = true;
        };

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
        # NDK prebuilt host tag depends on build system
        ndkHost = if pkgs.stdenv.isAarch64 then "linux-aarch64" else "linux-x86_64";

        commonTools = with pkgs; [
          bun
          curl
          unzip
          zip
          jq
          shellcheck
          git
          go
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages = commonTools ++ [ androidSdk ];
          ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
          NDK_ROOT = ndkRoot;
        };

        # `nix run .#build-geodat2srs` — build geodat2srs for Android targets
        apps.build-geodat2srs = {
          type = "app";
          program = toString (
            pkgs.writeShellScript "build-geodat2srs" ''
              set -euo pipefail
              SRC="$HOME/geodat2srs"
              # Write into the caller's working tree, not the read-only store copy.
              BIN="''${PROJECT_ROOT:-$PWD}/module/bin"
              if [ ! -d "$SRC" ]; then
                ${pkgs.git}/bin/git clone https://github.com/loss-and-quick/geodat2srs.git "$SRC"
              fi
              export PATH=${
                pkgs.lib.makeBinPath [
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

        # `nix run .#fetch-bin` — download core binaries into bin/
        apps.fetch-bin = {
          type = "app";
          program = toString (
            pkgs.writeShellScript "fetch-bin" ''
              export PATH=${
                pkgs.lib.makeBinPath [
                  pkgs.curl
                  pkgs.unzip
                  pkgs.coreutils
                ]
              }:$PATH
              # Target the caller's working tree, not the read-only store copy.
              export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
              exec ${pkgs.bash}/bin/bash "${self}/scripts/fetch-bin.sh" "$@"
            ''
          );
        };

        # `nix run .#build-webroot` — build the React app into webroot/
        apps.build-webroot = {
          type = "app";
          program = toString (
            pkgs.writeShellScript "build-webroot" ''
              export PATH=${
                pkgs.lib.makeBinPath [
                  pkgs.bun
                  pkgs.coreutils
                ]
              }:$PATH
              # Target the caller's working tree, not the read-only store copy.
              export PROJECT_ROOT="''${PROJECT_ROOT:-$PWD}"
              exec ${pkgs.bash}/bin/bash "${self}/scripts/build-webroot.sh" "$@"
            ''
          );
        };
      }
    );
}
