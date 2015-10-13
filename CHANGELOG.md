0.7
---

* Add support for AES key wrap in JWEs.
* Support A192GCM and A192CBC-HS384 algorithms.
* Switch to cryptonite library.

0.6.2
-----

* Remove dependency on `errors` package.

0.6.1
-----

* Minor internal changes to fix build on GHC 7.10.

0.6
---

* Change KeyId type to allow use of a UTCTime string for the identifier.
* Internal crypto fixes to prevent exceptions from external libraries.

0.5
---

* Add JwtEncoding type. Changes API of `Jwt.encode` and `Jwt.decode`.

0.4.2
-----

* Fix in the code for finding suitable JWKs for encoding/decoding.

0.4.1.1
-------

* Added `doctest` flag to cabal file to allow doctests to be disabled.

0.4.1
-----

* Add cprng-aes dependency to doctests to stop test failure on travis and nixos hydra builds.

0.4
---

* Changed use of `Jwt` type to represent an encoded JWT.
* Introduced `Payload` type to allow setting the `cty` header value correctly for nested JWTs.
* Added an explicit `Unsecured` type for a decoded JWT, to make it obvious when the content is not signed or encrypted.
* Fixed some bugs in JSON encoding and decoding of EC JWKs.

0.3.1
-----

Changed the signature of `Jwt.encode` to take a list of `Jwk` rather than a single key. The key will be selected from
the list based on the specified algorithms.

0.3
---

* New support for JWS validation using elliptic curve algorithms.
* Added `Jwt.encode` function which takes a JWK argument, allowing key data (currently the key ID) to be encoded in the token header.
