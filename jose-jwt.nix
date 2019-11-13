{ mkDerivation, aeson, attoparsec, base, bytestring, cereal
, containers, criterion, cryptonite, doctest, hspec, HUnit, memory
, mtl, QuickCheck, stdenv, text, time, transformers
, transformers-compat, unordered-containers, vector
}:
mkDerivation {
  pname = "jose-jwt";
  version = "0.8.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson attoparsec base bytestring cereal containers cryptonite
    memory mtl text time transformers transformers-compat
    unordered-containers vector
  ];
  testHaskellDepends = [
    aeson base bytestring cryptonite doctest hspec HUnit memory mtl
    QuickCheck text unordered-containers vector
  ];
  benchmarkHaskellDepends = [ base bytestring criterion cryptonite ];
  homepage = "http://github.com/tekul/jose-jwt";
  description = "JSON Object Signing and Encryption Library";
  license = stdenv.lib.licenses.bsd3;
}
