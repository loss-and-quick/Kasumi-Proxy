# Nix and NixOS

You don't need Nix to use or build Kasumi Proxy. If you already use it, the flake gives you a
ready dev shell, a reproducible desktop build and a NixOS module.

## Binary cache

Every release pushes the desktop build to the public [Cachix](https://www.cachix.org/) cache
`kasumi-proxy`. A flake's `nixConfig` does not apply to projects that consume it, so add the
cache to your own config:

```sh
cachix use kasumi-proxy
```

You can also add it by hand:

```nix
nixConfig = {
  extra-substituters = [ "https://kasumi-proxy.cachix.org" ];
  extra-trusted-public-keys = [
    "kasumi-proxy.cachix.org-1:V22nNqK4m1rSZRfuak86S1aY1eLlGhty05m8VtK25gM="
  ];
};
```

Without the cache everything still builds, only from source. Inside this repository, Nix asks
once whether to trust the flake's settings. Either accept, or pass `--accept-flake-config`.

## Installing the desktop app

```sh
nix build github:loss-and-quick/Kasumi-Proxy/vX.Y.Z#kasumi-desktop
```

Cache hits are per exact revision, so build a released tag.

## NixOS module

```nix
{
  inputs.kasumi-proxy.url = "github:loss-and-quick/Kasumi-Proxy";

  outputs = { nixpkgs, kasumi-proxy, ... }: {
    nixosConfigurations.your-host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        kasumi-proxy.nixosModules.default
        { programs.kasumi-proxy.enable = true; }
      ];
    };
  };
}
```

| Option | Default | Purpose |
| --- | --- | --- |
| `programs.kasumi-proxy.enable` | `false` | Installs the app and polkit. |
| `programs.kasumi-proxy.package` | this flake's `kasumi-desktop` | Uses a different build. |
| `programs.kasumi-proxy.helperSetuid` | `false` | Uses a setuid-root wrapper for the helper instead of setcap. |

The data-path helper gets `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_CHOWN` and `CAP_DAC_OVERRIDE`
through a `security.wrappers` setcap wrapper. The tunnel therefore comes up without a password
prompt, and the helper does not run as full root. If setcap does not work on your system, set
`helperSetuid = true`.

## Development in the Nix shell

`nix develop` gives you the pinned Rust, bun, shellcheck and the Tauri system libraries.
`nix develop .#android` adds the Android SDK/NDK for cross-builds. The build scripts are wrapped
as flake apps with all their dependencies:

```sh
nix develop --command cargo test --workspace
nix build .#kasumi-desktop                              # desktop package
nix run .#fetch-binaries -- android                     # cores into module/bin/
nix run .#package-release -- build/kasumi-proxy.zip     # full Android module zip
```
