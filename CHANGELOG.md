0.3.1
-----

Changed the signature of `Jwt.encode` to take a list of `Jwk` rather than a single key. The key will be selected from
the list based on the specified algorithms.

0.3
---

* New support for JWS validation using elliptic curve algorithms.
* Added `Jwt.encode` function which takes a JWK argument, allowing key data (currently the key ID) to be encoded in the token header.

