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
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # The desktop has no separate privileged core: the unprivileged GUI spawns the
    # kasumi-helper sidecar as root via pkexec for the tun + routes (the elevation
    # seam prefers /run/wrappers/bin/pkexec). polkit is on by default, but the
    # data-path can't elevate without it, so make the dependency explicit.
    security.polkit.enable = true;

    users.groups = lib.mkIf cfg.passwordlessElevation.enable {
      ${cfg.passwordlessElevation.group} = { };
    };

    # Allow the helper — and only the helper, by absolute store path — to be run
    # via pkexec without a prompt for the group. pkexec maps to the
    # org.freedesktop.policykit.exec action and exposes the target in
    # action.lookup("program"); matching the exact path means this grants no other
    # program. Caller-supplied env can't widen it: the GUI runs the fixed binary,
    # not `env …`, and forwards no LD_* across the boundary.
    security.polkit.extraConfig = lib.mkIf cfg.passwordlessElevation.enable ''
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
