{
  description = "Kasumi Proxy — transparent proxy (Xray-core / sing-box) — Rust backend + Tauri 2 app + React UI, shipped as a KSU/Magisk/APatch module";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    crane-tauri.url = "github:JPHutchins/crane-tauri";
    bun2nix.url = "github:nix-community/bun2nix?ref=2.1.0";
    bun2nix.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  # Pull prebuilt store paths (Rust toolchain, webkit, the devshell closure) from our
  # public Cachix cache so `nix develop` / `nix build` don't rebuild them. Honoured for
  # trusted users / with `--accept-flake-config` (CI sets accept-flake-config = true);
  # others can opt in prompt-free with `cachix use kasumi-proxy`. Pulls only — pushing
  # is done by the cachix-action in CI under an auth token.
  nixConfig = {
    extra-substituters = [ "https://kasumi-proxy.cachix.org" ];
    extra-trusted-public-keys = [
      "kasumi-proxy.cachix.org-1:V22nNqK4m1rSZRfuak86S1aY1eLlGhty05m8VtK25gM="
    ];
  };

  # The logic lives in nix/ (one file per concern); this flake just wires it up.
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      crane,
      crane-tauri,
      bun2nix,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          config.android_sdk.accept_license = true;
          # bun2nix → `bun2nix` (hook / fetchBunDeps); rust-overlay → `rust-bin`
          # (a toolchain carrying the android std targets for the daemon
          # cross-build). Neither overrides `pkgs.rustc`/`pkgs.cargo`, so crane's
          # host build is unaffected.
          overlays = [
            bun2nix.overlays.default
            rust-overlay.overlays.default
          ];
        };
        root = ./.;

        toolchain = import ./nix/toolchain.nix { inherit pkgs crane; };
        version = import ./nix/version.nix { inherit pkgs root; };
        cores = import ./nix/cores.nix { inherit pkgs root version; };
        desktop = import ./nix/desktop.nix {
          inherit
            pkgs
            root
            crane-tauri
            toolchain
            version
            cores
            ;
        };
      in
      {
        # Reproducible desktop build: `nix build .#kasumi-desktop` (GTK-wrapped,
        # cores bundled).
        packages = {
          inherit (desktop) frontend kasumi-desktop;
          default = desktop.kasumi-desktop;
          tauri-unwrapped = desktop.tauri.app;
        };

        checks.clippy = desktop.clippy;

        devShells = import ./nix/shells.nix { inherit pkgs toolchain; };

        apps = import ./nix/apps.nix { inherit pkgs self toolchain; };
      }
    );
}
