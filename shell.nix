let
pkgs = import <nixpkgs> {};
haskellPackages = pkgs.haskellPackages.override {
  extension = self: super: {
    joseJwt = self.callPackage ./. {};
    mtl     = self.callPackage ../nix-custom/mtl/2.1.3.1.nix {};
  };
};

in
pkgs.lib.overrideDerivation haskellPackages.joseJwt (attrs: {
  buildInputs = [ haskellPackages.cabalInstall ] ++ attrs.buildInputs;
})
