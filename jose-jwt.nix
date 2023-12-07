{ mkDerivation, aeson, attoparsec, base, bytestring, cereal
, containers, criterion, crypton, doctest, hspec, HUnit, memory
, mtl, QuickCheck, stdenv, text, time, transformers
, transformers-compat, unordered-containers, vector
}:
mkDerivation {
  pname = "jose-jwt";
  version = "0.9.6";
  src = ./.;
  libraryHaskellDepends = [
    aeson attoparsec base bytestring cereal containers crypton
    memory mtl text time transformers transformers-compat
    unordered-containers vector
  ];
  testHaskellDepends = [
    aeson base bytestring crypton doctest hspec HUnit memory mtl
    QuickCheck text unordered-containers vector
  ];
  benchmarkHaskellDepends = [ base bytestring criterion crypton ];
  homepage = "http://github.com/tekul/jose-jwt";
  description = "JSON Object Signing and Encryption Library";
  license = stdenv.lib.licenses.bsd3;
}
