{ compiler ? "ghc822" }:

let
  pkgs = import <nixpkgs> {};
  dontCheck = pkgs.haskell.lib.dontCheck;
  haskellPkgs = pkgs.haskell.packages."${compiler}".extend (self: super: {
    jose-jwt= self.callPackage ./jose-jwt.nix {};
  });
in
  {
    jose-jwt = haskellPkgs.jose-jwt;
  }
