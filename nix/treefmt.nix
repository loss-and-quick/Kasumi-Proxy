{inputs, self, ...}: {
  imports = [
    inputs.treefmt-nix.flakeModule
  ];

  perSystem = _: {
    treefmt.config = {
      projectRootFile = "flake.nix";
      settings = {
        global.excludes = [
          "LICENSE"
          ".gitattributes"
          "*.png"
          "*.svg"

          # Build artifacts (mirrors .gitignore)
          "node_modules/**"
          "target/**"
          "module/bin/**"
          "module/webroot/**"
          "src-tauri/binaries/**"
          "result"
          "*.lock"
          "*.tsbuildinfo"
          "*.wasm"
          "coverage/**"
          ".direnv/**"
          ".cache/**"
        ];
        # Restrict biome to frontend sources (mirrors biome.json's files.includes).
        formatter.biome = {
          excludes = [
            "frontend/src/generated/**"
          ];
        };
      };

      programs = {
        deadnix.enable = true;
        alejandra.enable = true;
        statix.enable = true;
        shellcheck.enable = true;
        rustfmt.enable = true;
        biome = {
          enable = true;
          # Settings are loaded from the root biome.json (the authoritative source
          # for IDE and CLI integration). Fields that are incompatible with treefmt's
          # evaluation context ($schema, vcs) are stripped before passing them on.
          settings = removeAttrs
            (builtins.fromJSON (builtins.readFile "${self}/biome.json"))
            [ "$schema" "vcs" ];
        };
      };
    };
  };
}
