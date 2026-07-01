{
  ...
}: {
  perSystem = { pkgs, toolchain, ... }:
    let
      inherit
        (toolchain)
        baseNative
        baseHook
        tauriLibs
        rustAndroid
        androidSdk
        ndkRoot
        ;
    in {
    # `nix develop` — rust + Tauri + node, no Android SDK (use `.#android`).
    devShells = {
      default = pkgs.mkShell {
        nativeBuildInputs = baseNative;
        buildInputs = tauriLibs;
        shellHook = baseHook;
      };

      # `nix develop .#android` — adds the (heavy) Android SDK/NDK for cross-builds.
      # rustAndroid leads so its target-carrying cargo/rustc shadow the host pair.
      android = pkgs.mkShell {
        nativeBuildInputs = [rustAndroid] ++ baseNative ++ [androidSdk];
        buildInputs = tauriLibs;
        ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
        NDK_ROOT = ndkRoot;
        shellHook = baseHook;
      };
    };
  };
}
