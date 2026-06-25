# NixOS integration: `programs.kasumi-proxy.enable = true` installs the desktop app
# and grants its data-path helper the Linux capabilities it needs via a
# `security.wrappers` setcap wrapper. The read-only Nix store can't be setcap'd, so
# the wrapper is the native grant (modelled on nixpkgs' throne): the GUI execs the
# helper with no password prompt and it runs least-privilege, not full root.
#
# `self` is threaded in from the flake so `package` can default to this repo's own
# build without the module having to know a system.
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

    helperSetuid = lib.mkEnableOption ''
      a setuid-root helper wrapper instead of the default setcap one. Less secure —
      the whole helper runs as root, not just its network ops — but a fallback for
      setups where setcap doesn't take. Mirrors throne's `tunMode.setuid`
    '';
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The data-path helper needs CAP_NET_ADMIN (tun + `ip` routing + tun2socks
    # fwmark), CAP_NET_RAW (the test-core uplink bind), and CHOWN + DAC_OVERRIDE
    # (helper socket + run_dir). The read-only store can't carry file caps, so grant
    # them through a wrapper in /run/wrappers/bin the GUI execs directly — no prompt,
    # and the helper runs as the calling user rather than root. The cap set mirrors
    # the helper's in-code keep-set (see capabilities.rs); `+ep` = effective+permitted.
    # setuid is the fallback for setups where setcap doesn't take.
    security.wrappers.kasumi-helper = {
      source = "${cfg.package}/bin/kasumi-helper";
      owner = "root";
      group = "root";
      setuid = lib.mkIf cfg.helperSetuid true;
      capabilities = lib.mkIf (
        !cfg.helperSetuid
      ) "cap_net_admin,cap_net_raw,cap_chown,cap_dac_override+ep";
    };
  };
}
