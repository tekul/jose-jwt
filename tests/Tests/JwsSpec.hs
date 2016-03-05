{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Tests.JwsSpec where

import Test.Hspec
import Test.HUnit hiding (Test)

import Data.Aeson (decodeStrict')
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 ()
import Data.Word (Word64)
import Crypto.Hash.Algorithms (SHA256(..))
import Crypto.MAC.HMAC (HMAC, hmac)
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECCGenerate
import Crypto.PubKey.ECC.Types (CurveName(..), getCurveByName)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSAPKCS15
import Crypto.Random (withDRG, drgNewTest)

import Jose.Jwt
import Jose.Jwa
import qualified Jose.Internal.Base64 as B64
import qualified Jose.Jws as Jws


testRNG = drgNewTest (w, w, w, w, w) where w = 1 :: Word64

fstWithRNG = fst . withDRG testRNG

{-- Examples from the JWS appendix A --}

spec :: Spec
spec =
    describe "JWS encoding and decoding" $ do
      context "when using JWS Appendix A.1 data" $ do
        let a11decoded = Right (defJwsHdr {jwsAlg = HS256, jwsTyp = Just "JWT"}, a11Payload)
        it "decodes the JWT to the expected header and payload" $
          Jws.hmacDecode hmacKey a11 @?= a11decoded

        it "encodes the payload to the expected JWT" $
          signWithHeader a11mac a11Header a11Payload @?= a11

        it "decodes the payload using the JWK" $ do
          let Just k11 = decodeStrict' a11jwk
          fstWithRNG (decode [k11] Nothing a11) @?= fmap Jws a11decoded

        it "encodes/decodes using HS512" $
          hmacRoundTrip HS512 a11Payload

        it "encodes/decodes using HS384" $
          hmacRoundTrip HS384 a11Payload

      context "when using JWS Appendix A.2 data" $ do
        it "decodes the JWT to the expected header and payload" $
          Jws.rsaDecode rsaPublicKey a21 @?= Right (defJwsHdr {jwsAlg = RS256}, a21Payload)

        it "decodes the JWT to the expected header and payload with the JWK" $ do
          let Just k21 = decodeStrict' a21jwk
          fstWithRNG (decode [k21] (Just (JwsEncoding RS256)) a21) @?= (Right $ Jws (defJwsHdr {jwsAlg = RS256}, a21Payload))

        it "encodes the payload to the expected JWT" $ do
          let sign = either (error "Sign failed") id . RSAPKCS15.sign Nothing (Just SHA256) rsaPrivateKey
          signWithHeader sign a21Header a21Payload @?= a21

        it "encodes/decodes using RS256" $
          rsaRoundTrip RS256 a21Payload

        it "encodes/decodes using RS384" $
          rsaRoundTrip RS384 a21Payload

        it "encodes/decodes using RS512" $
          rsaRoundTrip RS512 a21Payload

      context "when using JWS Appendix A.3 data" $ do
        let a31decoded = Right (defJwsHdr {jwsAlg = ES256}, a31Payload)
        it "decodes the JWT to the expected header and payload" $ do
          let Just k31 = decodeStrict' a31jwk
          fstWithRNG (decode [k31] Nothing a31) @?= fmap Jws a31decoded

        it "encodes/decodes using ES256" $ do
          keypair <- ECCGenerate.generate (getCurveByName SEC_p256k1)
          ecRoundTrip keypair ES256 a31Payload

        it "encodes/decodes using ES384" $ do
          keypair <- ECCGenerate.generate (getCurveByName SEC_p384r1)
          ecRoundTrip keypair ES384 a31Payload

        it "encodes/decodes using ES512" $ do
          keypair <- ECCGenerate.generate (getCurveByName SEC_p521r1)
          ecRoundTrip keypair ES512 a31Payload

      context "when using an unsecured JWT" $ do
        it "returns an error if alg is unset" $
          fstWithRNG (decode [] Nothing jwt61) @?= Left (BadAlgorithm "JWT is unsecured but expected 'alg' was not 'none'")
        it "returns an error if alg is is not 'none'" $
          fstWithRNG (decode [] (Just (JwsEncoding RS256)) jwt61) @?= Left (BadAlgorithm "JWT is unsecured but expected 'alg' was not 'none'")
        it "decodes the JWT to the expected header and payload" $
          fstWithRNG (decode [] (Just (JwsEncoding None)) jwt61) @?= Right (Unsecured jwt61Payload)


signWithHeader sign hdr payload = B.intercalate "." [hdrPayload, B64.encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map B64.encode [hdr, payload]

hmacRoundTrip a msg = let Right (Jwt encoded) = Jws.hmacEncode a "asecretkey" msg
                     in  Jws.hmacDecode "asecretkey" encoded @?= Right (defJwsHdr {jwsAlg = a}, msg)

rsaRoundTrip a msg = let Right (Jwt encoded) = fstWithRNG (Jws.rsaEncode a rsaPrivateKey msg)
                     in  Jws.rsaDecode rsaPublicKey encoded @?= Right (defJwsHdr {jwsAlg = a}, msg)

ecRoundTrip (publicKey, privateKey) a msg =
  let Right (Jwt encoded) = fstWithRNG (Jws.ecEncode a privateKey msg)
  in  Jws.ecDecode publicKey encoded @?= Right (defJwsHdr {jwsAlg = a}, msg)

-- Unsecured JWT from section 6.1
jwt61 = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
jwt61Payload = a11Payload

a11Header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}" :: B.ByteString
a11Payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
a11 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
a11jwk = "{\"kty\":\"oct\", \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }"


a21Header = "{\"alg\":\"RS256\"}" :: B.ByteString
a21Payload = a11Payload
a21 = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
a21jwk = "{\"kty\":\"RSA\", \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\", \"e\":\"AQAB\", \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"}"

a31Header = "{\"alg\":\"ES256\"}" :: B.ByteString
a31Payload = a11Payload
a31 = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
a31jwk = "{\"kty\":\"EC\", \"crv\":\"P-256\", \"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\", \"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\", \"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\" }"


hmacKey = B.pack [
    3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
    143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
    46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
    98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
    208, 128, 163]

-- N
rsaModulus :: Integer
rsaModulus = 20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601


rsaExponent = 65537 :: Integer

-- D
rsaPrivateExponent :: Integer
rsaPrivateExponent = 2358310989939619510179986262349936882924652023566213765118606431955566700506538911356936879137503597382515919515633242482643314423192704128296593672966061810149316320617894021822784026407461403384065351821972350784300967610143459484324068427674639688405917977442472804943075439192026107319532117557545079086537982987982522396626690057355718157403493216553255260857777965627529169195827622139772389760130571754834678679842181142252489617665030109445573978012707793010592737640499220015083392425914877847840457278246402760955883376999951199827706285383471150643561410605789710883438795588594095047409018233862167884701

rsaPrivateKey = RSA.PrivateKey
    { RSA.private_pub = rsaPublicKey
    , RSA.private_d = rsaPrivateExponent
    , RSA.private_q = 0
    , RSA.private_p = 0
    , RSA.private_dP = 0
    , RSA.private_dQ = 0
    , RSA.private_qinv = 0
    }

rsaPublicKey = RSA.PublicKey
    { RSA.public_size = 256
    , RSA.public_n = rsaModulus
    , RSA.public_e = rsaExponent
    }

a11mac :: B.ByteString -> HMAC SHA256
a11mac = hmac hmacKey
