# NixOS integration: `programs.kasumi-proxy.enable = true;` installs the desktop
# app and makes sure polkit is present for its root re-exec. Password-free
# elevation is intentionally not here yet — see the README.
#
# `self` is threaded in from the flake so `package` can default to this repo's
# own build without the module having to know a system.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.programs.kasumi-proxy;
in
{
  options.programs.kasumi-proxy = {
    enable = lib.mkEnableOption "Kasumi Proxy, the transparent-proxy desktop app";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.kasumi-desktop;
      defaultText = lib.literalExpression "kasumi-proxy.packages.\${system}.kasumi-desktop";
      description = "The kasumi-desktop package to install.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The desktop has no privileged sidecar: it re-execs the whole GUI as root via
    # pkexec to bring up the tun + routes (the Linux elevation seam prefers
    # /run/wrappers/bin/pkexec). polkit is on by default, but the data-path can't
    # elevate without it, so make the dependency explicit.
    security.polkit.enable = true;
  };
}
