A Haskell implementation of the JSON Object Signing and Encryption (JOSE) specifications and the related [JWT specification](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token), as used, for example, in [OpenID Connect](http://openid.net/connect/).

This library is mainly intended for creating and consuming tokens which are JWTs. The JWT specification was split into JWE and JWS during its development and thus does not contain much. Basically, a JWT is either a JWS or a JWE depending on whether it is signed or encrypted (this implementation doesn't support plaintext JWTs). It is encoded as a sequence of base64 strings separated by '.' characters. This is now referred to as "compact serialization". The additional "JSON serialization" is not currently supported.

Technically, the content of a JWT should be JSON (unless it's a nested JWT), but the library doesn't care - it only requires a bytestring. The calling application should verify that the content is valid as appropriate.

A simple JWS example in ghci to illustrate:

    > :module Jose.Jws Jose.Jwa
    > hmacEncode HS384 "somehmackey" "my JSON message"
    "eyJhbGciOiJIUzM4NCJ9.bXkgSlNPTiBtZXNzYWdl.cNfy9RU8XwOWMr35K562dLOpHnZn3hypK0yrL5cZ3LqLD3FMewiY7Cs45r2auKbw"
    Jose.Jws Jose.Jwa> hmacDecode "somehmackey" "eyJhbGciOiJIUzM4NCJ9.bXkgSlNPTiBtZXNzYWdl.cNfy9RU8XwOWMr35K562dLOpHnZn3hypK0yrL5cZ3LqLD3FMewiY7Cs45r2auKbw"
    Right (JwtHeader {alg = HS384, enc = Nothing, typ = Nothing, cty = Nothing},"my JSON message")kkkk

Tring to decode with a different key would return a `Left BadSignature`.

[![Build Status](https://travis-ci.org/tekul/jose.svg?branch=master)](https://travis-ci.org/tekul/jose)
