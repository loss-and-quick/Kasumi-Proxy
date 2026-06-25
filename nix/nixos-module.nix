# NixOS integration: `programs.kasumi-proxy.enable = true;` installs the desktop
# app and ensures polkit is present for the data-path's root helper. An opt-in
# rule grants that helper password-free to a group.
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
  helper = "${cfg.package}/bin/kasumi-helper";
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

    passwordlessElevation = {
      enable = lib.mkEnableOption ''
        a polkit rule letting members of the configured group start the data-path
        without a password prompt. It is scoped to the kasumi-helper binary only —
        the small privileged sidecar, not the GUI — so it grants nothing else'';

      group = lib.mkOption {
        type = lib.types.str;
        default = "kasumi-proxy";
        description = ''
          Group whose members may run the helper without authenticating. Members
          gain unprompted root for the tunnel; add only trusted users. The group is
          created automatically.
        '';
      };
    };

    helperCaps = {
      enable = lib.mkEnableOption ''
        running the data-path helper via a `security.wrappers.kasumi-helper` setcap
        wrapper instead of elevating it as root through pkexec. The GUI execs the
        wrapper directly — no password prompt — and the helper runs as the calling
        user with only the data-path caps (NET_ADMIN, NET_RAW, CHOWN, DAC_OVERRIDE),
        not full root. Supersedes `passwordlessElevation` (which grants unprompted
        root); prefer this for the smaller blast radius
      '';

      setuid = lib.mkEnableOption ''
        the setuid (root) wrapper instead of the setcap default — closer to the old
        pkexec behaviour, less secure (the whole helper runs as root). Enable only
        if setcap doesn't work in your setup
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # polkit drives the default pkexec elevation; explicit even when the caps
    # wrapper below makes it unused.
    security.polkit.enable = true;

    users.groups = lib.mkIf cfg.passwordlessElevation.enable {
      ${cfg.passwordlessElevation.group} = { };
    };

    # The passwordless caps wrapper: a setcap kasumi-helper in /run/wrappers/bin
    # the GUI execs directly. The cap set mirrors the helper's in-code keep-set
    # (see capabilities.rs); `+ep` = effective+permitted. setuid (root) is the
    # fallback when setcap misbehaves. Mutually exclusive, as in nixpkgs' throne.
    security.wrappers.kasumi-helper = lib.mkIf cfg.helperCaps.enable {
      source = "${cfg.package}/bin/kasumi-helper";
      owner = "root";
      group = "root";
      setuid = lib.mkIf cfg.helperCaps.setuid true;
      capabilities = lib.mkIf (
        !cfg.helperCaps.setuid
      ) "cap_net_admin,cap_net_raw,cap_chown,cap_dac_override+ep";
    };

    # Run the helper — and only the helper, matched by absolute store path in the
    # org.freedesktop.policykit.exec action — via pkexec without a prompt for the
    # group. The GUI execs the fixed binary (no `env …`, no LD_* forwarded), so the
    # caller can't widen it. Unused when helperCaps is on (the wrapper is already
    # passwordless).
    security.polkit.extraConfig =
      lib.mkIf (cfg.passwordlessElevation.enable && !cfg.helperCaps.enable)
        ''
          polkit.addRule(function(action, subject) {
            if (action.id == "org.freedesktop.policykit.exec" &&
                action.lookup("program") == "${helper}" &&
                subject.isInGroup("${cfg.passwordlessElevation.group}")) {
              return polkit.Result.YES;
            }
          });
        '';
  };
}
