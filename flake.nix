{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    haskell-flake.url = "github:srid/haskell-flake";
  };
  outputs = inputs@{ self, nixpkgs, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = nixpkgs.lib.systems.flakeExposed;
      imports = [ inputs.haskell-flake.flakeModule ];

      perSystem = { self', pkgs, ... }: 
        let
          inherit (pkgs.haskell.lib)
            overrideCabal doJailbreak dontCheck dontHaddock justStaticExecutables;
        in
        {

        # Typically, you just want a single project named "default". But
        # multiple projects are also possible, each using different GHC version.
        haskellProjects.default = {
          # The base package set representing a specific GHC version.
          # By default, this is pkgs.haskellPackages.
          # You may also create your own. See https://community.flake.parts/haskell-flake/package-set
          # basePackages = pkgs.haskellPackages;

          # Extra package information. See https://community.flake.parts/haskell-flake/dependency
          #
          # Note that local packages are automatically included in `packages`
          # (defined by `defaults.packages` option).
          #
          packages = {
            # This doesn't seem to work since ram isn't in nixpkgs?
            # It works using the otherOverlays code below.
            # ram.source = "0.22.0";
          };

          otherOverlays = [
            (hself: hsuper: {
                ram = (hself.callHackageDirect {
                  pkg = "ram";
                  ver = "0.22.0";
                  sha256 = "sha256-Z7PnMu61TG/e9QEylTJQC68YAkltCufP3FD4oOBDj9c=";
                } { });
            })

          ];

          settings = {
            #  aeson = {
            #    check = false;
            #  };
            #  relude = {
            #    haddock = false;
            #    broken = false;
            #  };
          };

          devShell = {
            # Enabled by default
            # enable = true;

            # Programs you want to make available in the shell.
            # Default programs can be disabled by setting to 'null'
            # tools = hp: { fourmolu = hp.fourmolu; ghcid = null; };

            # Check that haskell-language-server works
            # hlsCheck.enable = true; # Requires sandbox to be disabled
          };
        };

        # haskell-flake doesn't set the default package, but you can do it here.
        packages.default = self'.packages.jose-jwt;
      };
    };
}
