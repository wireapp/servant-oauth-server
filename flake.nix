{
  description = "Dev Setup";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {nixpkgs, flake-utils, ...}:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        # Avoids unnecessary recompiles
        filteredSource = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let baseName = baseNameOf (toString path);
            in pkgs.lib.cleanSourceFilter path type && !(
              baseName == "flake.nix" ||
              baseName == "flake.lock" ||
              baseName == "dist-newstyle" ||
              builtins.match "^cabal\.project\..*$" baseName != null ||
              baseName == "hls.sh" ||
              baseName == ".envrc" ||
              baseName == "hie.yaml" ||
              baseName == ".hlint.yaml" ||
              baseName == ".hspec" ||
              baseName == "ci"
            );
        };
        ghcOverrides = hself: hsuper: rec {
          servant-oauth-server =  pkgs.haskell.lib.overrideSrc (hsuper.callPackage ./default.nix {}) {
            src = filteredSource;
          };
        };
        ghc924Pkgs = pkgs.haskell.packages.ghc924.override {
          overrides = ghcOverrides;
        };
        ghc902Pkgs = pkgs.haskell.packages.ghc902.override {
          overrides = ghcOverrides;
        };
        ghc8107Pkgs = pkgs.haskell.packages.ghc8107.override {
          overrides = ghcOverrides;
        };
        ghc884Pkgs = pkgs.haskell.packages.ghc884.override {
          overrides = ghcOverrides;
        };
      in rec {
        packages = rec {
          dev-env = ghc902Pkgs.shellFor {
            packages = p: [p.servant-oauth-server];
            buildInputs = [
              pkgs.haskellPackages.cabal-install
              (pkgs.haskell-language-server.override {supportedGhcVersions = ["902"];})
              pkgs.haskellPackages.implicit-hie
              pkgs.cabal2nix
              pkgs.ormolu
              pkgs.hlint
              pkgs.ghcid
              pkgs.haskellPackages.cabal-fmt

              # For cabal
              pkgs.pkg-config
              pkgs.binutils
            ];
          };
          servant-oauth-server-ghc924 = ghc924Pkgs.servant-oauth-server;
          servant-oauth-server-ghc902 = ghc902Pkgs.servant-oauth-server;
          servant-oauth-server-ghc8107 = ghc8107Pkgs.servant-oauth-server;
          servant-oauth-server-ghc884 = ghc884Pkgs.servant-oauth-server;
          ormolu = pkgs.ormolu;
        };
        defaultPackage = packages.dev-env;
    });
}
