# The proxy cores (xray / sing-box / tun2socks / geodat2srs) for the desktop nix
# build, fetched at the EXACT pinned versions (fixed-output, reproducible). The
# first three are prebuilt static Go archives (unzip / untar); geodat2srs is
# built from source via buildGoModule (dynamically linked against nixpkgs's glibc,
# fine within the nix store). Hashes live in scripts/core-hashes.json, regenerated
# from core-versions.sh by scripts/update-core-hashes.sh (the release CI runs it
# on a version bump).
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
  geodat2srsSrc = pkgs.fetchFromGitHub {
    owner = "loss-and-quick";
    repo = "geodat2srs";
    rev = version.geodat2srsRev;
    # `fetchFromGitHub`'s leaveDotGit would also need deepClone for a hash that
    # matches a shallow checkout — neither is needed here (no embedded VCS info).
    hash = coreHashes."geodat2srs-src";
  };

  # geodat2srs has no release artifacts, so build it from source at the pinned
  # commit.
  geodat2srs = pkgs.buildGoModule {
    pname = "geodat2srs";
    # No upstream version tags — use the commit short-hash as the version string.
    version = builtins.substring 0 7 version.geodat2srsRev;
    src = geodat2srsSrc;
    vendorHash = coreHashes."geodat2srs-vendor";
    subPackages = [ "." ];
  };
in
{
  # Assemble the four cores under plain names — the desktop Platform looks for
  # `{KASUMI_BIN_DIR}/{xray,sing-box,tun2socks,geodat2srs}` (src-tauri/src/desktop/paths.rs).
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
        install -m755 ${geodat2srs}/bin/geodat2srs $out/bin/geodat2srs
        chmod +x $out/bin/*
      '';
}
