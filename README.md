# `jose-jwt`

A Haskell implementation of the JSON Object Signing and Encryption (JOSE) specifications and the related [JWT specification](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token), as used, for example, in [OpenID Connect](http://openid.net/connect/).

## Background

The [JWT specification](https://tools.ietf.org/html/rfc7519) was split into [`JWS`](https://www.rfc-editor.org/rfc/rfc7515.html) and [`JWE`](https://www.rfc-editor.org/rfc/rfc7516.html) during its development so does not contain much. A JWT is either a JWS or a JWE depending on whether it is signed or encrypted. It is encoded as a sequence of base64 strings separated by '.' characters [1].

Technically, the content of a JWT should be JSON (unless it's a nested JWT), but this library doesn't care - it only requires a bytestring. The application should verify that the content is valid. Exactly what that means will depend on what you are using JWTs for.

## Examples

You can either use the high-level `encode` and `decode` functions in the [`Jwt`](https://hackage.haskell.org/package/jose-jwt/docs/Jose-Jwt.html) module or specific functions in the [`Jws`](https://hackage.haskell.org/package/jose-jwt/docs/Jose-Jws.html) and [`Jwe`](https://hackage.haskell.org/package/jose-jwt/docs/Jose-Jwe.html) modules.

The following examples can be entered directly into `ghci`. Use

    > :set -XOverloadedStrings

to begin with.

### JWS signing example with a symmetric HMAC algorithm

HMAC is a good choice when both signer and verifier have a copy of the key.

    > import Jose.Jws (hmacEncode, hmacDecode)
    > import Jose.Jwa (JwsAlg(HS256))
    >
    > hmacEncode HS256 "aRANDOMlygeneratedkey" "my JSON message"
    Right (Jwt {unJwt = "eyJhbGciOiJIUzI1NiJ9.bXkgSlNPTiBtZXNzYWdl.lTJx7ECLwYF3P7WbrrUpcp_2SdLiFXaDwK-PXcipt5Q"})
    > hmacDecode "aRANDOMlygeneratedkey" "eyJhbGciOiJIUzI1NiJ9.bXkgSlNPTiBtZXNzYWdl.lTJx7ECLwYF3P7WbrrUpcp_2SdLiFXaDwK-PXcipt5Q"
    Right (JwsHeader {jwsAlg = HS256, jwsTyp = Nothing, jwsCty = Nothing, jwsKid = Nothing},"my JSON message")

Trying to decode with a different key would return a `Left BadSignature` [2].

### JWS signing using Ed25519 private key

Some situations require the use of public key cryptography for signing. For example, only a trusted party is allowed to create a signed token, but it must be verified by others.

Elliptic-curve EdDSA signing and verification are supported as defined in [RFC 8037](https://tools.ietf.org/html/rfc8037), as well as the older RSA JWS algorithms.

    > import Jose.Jwt
    > import Jose.Jwk
    > import Jose.Jwa (JwsAlg(EdDSA))
    > import Data.ByteString (ByteString)
    > import Data.Aeson (decodeStrict)
    >
    > jsonJwk = "{\"kty\":\"OKP\", \"crv\":\"Ed25519\", \"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\", \"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}" :: ByteString
    > Just jwk = decodeStrict jsonJwk :: Maybe Jwk
    > Jose.Jwt.encode [jwk] (JwsEncoding EdDSA) (Claims "public claims")
    Right (Jwt {unJwt = "eyJhbGciOiJFZERTQSJ9.cHVibGljIGNsYWltcw.xYekeeGSQVpnQbl16lOCqFcmYsUj3goSTrZ4UBQqogjHLrvFUaVJ_StBqly-Tb-0xvayjUMM4INYBTwFMt_xAQ"})

To verify the JWT you would use the `Jose.Jwt.decode` function with the corresponding public key.

More examples can be found in the [package documentation](https://hackage.haskell.org/package/jose-jwt).

### Build Status
![Build Status](https://github.com/tekul/jose-jwt/workflows/Haskell%20CI/badge.svg)


[1] This is now referred to as "compact serialization". The additional "JSON serialization" is not supported in this library.

[2] Note that a real key for HMAC256 should be a much longer, random string of bytes. See, for example,
[this stackexchange answer](https://crypto.stackexchange.com/a/34866).

