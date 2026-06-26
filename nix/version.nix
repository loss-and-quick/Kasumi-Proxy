# Versions read from the single sources of truth: the product version from
# module/module.prop, the pinned binary versions from scripts/binary-versions.sh.
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

  # Pinned binary versions, shared with the fetch scripts so the nix desktop build
  # ships the SAME versions as the Android zip / CI installers. A line reads
  # `NAME="${NAME:-vX.Y.Z}"`; pull the default between `:-` and `}`.
  pinnedVersion =
    name:
    let
      line = lib.findFirst (l: lib.hasPrefix "${name}=" l) "" (
        lib.splitString "\n" (builtins.readFile (root + "/scripts/binary-versions.sh"))
      );
      m = builtins.match ".*:-([^}\"]+).*" line;
    in
    if m == null then throw "version ${name} not found in binary-versions.sh" else builtins.head m;

  singboxVer = pinnedVersion "SINGBOX_VERSION";
  # pin a commit on main (binary-versions.sh).
  geodat2srsRev = pinnedVersion "GEODAT2SRS_REV";
in
{
  inherit appVersion singboxVer geodat2srsRev;
  # Exposed so nix/binaries.nix can resolve a binary's pinned tag from the
  # version_var named in scripts/binaries.json (the shared asset catalog).
  inherit pinnedVersion;
  xrayVer = pinnedVersion "XRAY_VERSION";
  tun2socksVer = pinnedVersion "TUN2SOCKS_VERSION";
  singboxVerBare = lib.removePrefix "v" singboxVer;
}
