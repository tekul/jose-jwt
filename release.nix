{ compiler ? "default" }:

let
  pkgs = import <nixpkgs> {};
  dontCheck = pkgs.haskell.lib.dontCheck;
  doBenchmark = pkgs.haskell.lib.doBenchmark;
  hPkgs = if compiler == "default"
              then pkgs.haskellPackages
              else pkgs.haskell.packages.${compiler};

  haskellPkgs = hPkgs.extend (self: super: {
    jose-jwt = doBenchmark( self.callPackage ./jose-jwt.nix {} );
  });
in
  {
    jose-jwt = haskellPkgs.jose-jwt;
  }
