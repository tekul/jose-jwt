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

