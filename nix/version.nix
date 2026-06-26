# Versions read from the single sources of truth: the product version from
# module/module.prop, the pinned core versions from scripts/core-versions.sh.
{ pkgs, root }:
let
  lib = pkgs.lib;

  # Product version — the Android zip uses `vX.Y.Z`; nix/cargo want bare `X.Y.Z`.
  # A bump in module.prop re-versions the nix artifacts too.
  appVersion =
    let
      propLine = lib.findFirst (l: lib.hasPrefix "version=" l) "version=0.0.0" (
        lib.splitString "\n" (builtins.readFile (root + "/module/module.prop"))
      );
    in
    lib.removePrefix "v" (lib.removePrefix "version=" propLine);

  # Pinned core versions, shared with the fetch scripts so the nix desktop build
  # ships the SAME versions as the Android zip / CI installers. A line reads
  # `NAME="${NAME:-vX.Y.Z}"`; pull the default between `:-` and `}`.
  coreVersion =
    name:
    let
      line = lib.findFirst (l: lib.hasPrefix "${name}=" l) "" (
        lib.splitString "\n" (builtins.readFile (root + "/scripts/core-versions.sh"))
      );
      m = builtins.match ".*:-([^}\"]+).*" line;
    in
    if m == null then throw "core version ${name} not found in core-versions.sh" else builtins.head m;

  singboxVer = coreVersion "SINGBOX_VERSION";
  # pin a commit on main (core-versions.sh).
  geodat2srsRev = coreVersion "GEODAT2SRS_REV";
in
{
  inherit appVersion singboxVer geodat2srsRev;
  # Exposed so nix/cores.nix can resolve a core's pinned tag from the version_var
  # named in scripts/cores.json (the shared asset catalog).
  inherit coreVersion;
  xrayVer = coreVersion "XRAY_VERSION";
  tun2socksVer = coreVersion "TUN2SOCKS_VERSION";
  singboxVerBare = lib.removePrefix "v" singboxVer;
}
