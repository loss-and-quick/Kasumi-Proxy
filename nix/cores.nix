# The proxy cores (xray / sing-box / tun2socks) for the desktop nix build,
# fetched at the EXACT pinned versions (fixed-output, reproducible). They're
# static Go binaries — no patchelf needed on NixOS. Hashes live in
# scripts/core-hashes.json, regenerated from core-versions.sh by
# scripts/update-core-hashes.sh (the release CI runs it on a version bump).
{
  pkgs,
  root,
  version,
}:
let
  coreHashes = builtins.fromJSON (builtins.readFile (root + "/scripts/core-hashes.json"));

  xraySrc = pkgs.fetchurl {
    url = "https://github.com/XTLS/Xray-core/releases/download/${version.xrayVer}/Xray-linux-64.zip";
    hash = coreHashes.xray;
  };
  tun2socksSrc = pkgs.fetchurl {
    url = "https://github.com/xjasonlyu/tun2socks/releases/download/${version.tun2socksVer}/tun2socks-linux-amd64.zip";
    hash = coreHashes.tun2socks;
  };
  singboxSrc = pkgs.fetchurl {
    url = "https://github.com/SagerNet/sing-box/releases/download/${version.singboxVer}/sing-box-${version.singboxVerBare}-linux-amd64.tar.gz";
    hash = coreHashes."sing-box";
  };
in
{
  # Assemble the three cores under plain names — the desktop Platform looks for
  # `{KASUMI_BIN_DIR}/{xray,sing-box,tun2socks}` (src-tauri/src/desktop/paths.rs).
  desktopCores =
    pkgs.runCommand "kasumi-desktop-cores-${version.appVersion}"
      {
        nativeBuildInputs = [
          pkgs.unzip
          pkgs.gnutar
        ];
      }
      ''
        mkdir -p $out/bin tmp && cd tmp
        unzip -j ${xraySrc} xray -d $out/bin
        unzip -j ${tun2socksSrc} -d t2s
        install -m755 "$(find t2s -type f -name 'tun2socks*' | head -1)" $out/bin/tun2socks
        tar xzf ${singboxSrc}
        install -m755 "$(find . -type f -name sing-box | head -1)" $out/bin/sing-box
        chmod +x $out/bin/*
      '';
}
