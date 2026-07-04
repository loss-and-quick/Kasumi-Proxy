{
  description = "Kasumi Proxy — transparent proxy (Xray-core / sing-box) — Rust backend + Tauri 2 app + React UI, shipped as a KSU/Magisk/APatch module";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    crane-tauri.url = "github:JPHutchins/crane-tauri";
    bun2nix.url = "github:nix-community/bun2nix?ref=2.1.0";
    bun2nix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
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
  #
  # perSystem → system-dependent outputs (packages/checks/devShells/apps/formatter).
  # flake     → system-independent outputs (NixOS module).
  outputs = { self, nixpkgs, flake-parts, crane, crane-tauri, bun2nix, rust-overlay, ... }@inputs:
    let
      flakeOutputs = flake-parts.lib.mkFlake { inherit inputs; } {
        systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];

        _module.args = {
          inherit self;
          crane-tauri = inputs.crane-tauri;
        };

        perSystem = { system, ... }:
          let
            pkgs = import inputs.nixpkgs {
              inherit system;
              config.allowUnfree = true;
              config.android_sdk.accept_license = true;
              overlays = [
                inputs.bun2nix.overlays.default
                inputs.rust-overlay.overlays.default
              ];
            };
            toolchain = import ./nix/toolchain.nix { inherit pkgs; crane = inputs.crane; };
            version = import ./nix/version.nix { inherit pkgs self; };
          in
          {
            _module.args = {
              inherit pkgs toolchain version;
              binaries = import ./nix/binaries.nix { inherit pkgs self version; };
            };
          };

        imports = [
          ./nix/desktop.nix
          ./nix/shells.nix
          ./nix/apps.nix
          ./nix/treefmt.nix
        ];

        flake = {
          # `programs.kasumi-proxy.enable = true;` — see nix/nixos-module.nix.
          nixosModules.default = import ./nix/nixos-module.nix { inherit self; };
        };
      };

      # Provide formatter output explicitly to satisfy flake schema
    in
    flakeOutputs;
}
