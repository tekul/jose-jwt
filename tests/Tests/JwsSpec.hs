{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Tests.JwsSpec where

import Test.Hspec
import Test.HUnit hiding (Test)

import Data.Aeson (decodeStrict')
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 ()
import qualified Crypto.Hash.SHA256 as SHA256
import Crypto.MAC.HMAC (hmac)
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSAPKCS15
import Crypto.PubKey.HashDescr
import Crypto.Random (CPRG(..))

import Jose.Jwt
import Jose.Jwa
import qualified Jose.Internal.Base64 as B64
import qualified Jose.Jws as Jws

-- Test CPRG which just produces a stream of '255' bytes
data RNG = RNG deriving (Show, Eq)

instance CPRG RNG where
    cprgCreate              = undefined
    cprgSetReseedThreshold  = undefined
    cprgGenerate n g        = (B.replicate n 255, g)
    cprgGenerateWithEntropy = undefined
    cprgFork                = undefined

{-- Examples from the JWS appendix A --}

spec :: Spec
spec =
    describe "JWS encoding and decoding" $ do
      context "when using JWS Appendix A.1 data" $ do
        let a11decoded = Right (defJwsHdr {jwsAlg = HS256, jwsTyp = Just "JWT"}, a11Payload)
        it "decodes the JWT to the expected header and payload" $
          Jws.hmacDecode hmacKey a11 @?= a11decoded

        it "encodes the payload to the expected JWT" $
          encode a11mac a11Header a11Payload @?= a11

        it "decodes the payload using the JWK" $ do
          let Just k11 = decodeStrict' a11jwk
          fst (decode RNG [k11] a11) @?= fmap Jws a11decoded

      context "when using JWS Appendix A.2 data" $ do
        it "decodes the JWT to the expected header and payload" $
          Jws.rsaDecode rsaPublicKey a21 @?= Right (defJwsHdr {jwsAlg = RS256}, a21Payload)

        it "encodes the payload to the expected JWT" $ do
          let sign = either (error "Sign failed") id . RSAPKCS15.sign Nothing hashDescrSHA256 rsaPrivateKey
          encode sign a21Header a21Payload @?= a21

        it "encodes/decodes using RS256" $
          rsaRoundTrip RS256 a21Payload

        it "encodes/decodes using RS384" $
          rsaRoundTrip RS384 a21Payload

        it "encodes/decodes using RS512" $
          rsaRoundTrip RS512 a21Payload

encode sign hdr payload = B.intercalate "." [hdrPayload, B64.encode $ sign hdrPayload]
  where
    hdrPayload = B.intercalate "." $ map B64.encode [hdr, payload]

rsaRoundTrip a msg = let Right encoded = fst $ Jws.rsaEncode RNG a rsaPrivateKey msg
                     in  Jws.rsaDecode rsaPublicKey encoded @?= Right (defJwsHdr {jwsAlg = a}, msg)

a11Header = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}" :: B.ByteString
a11Payload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}"
a11 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
a11jwk = "{\"kty\":\"oct\", \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\" }"


a21Header = "{\"alg\":\"RS256\"}" :: B.ByteString
a21Payload = a11Payload
a21 = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"

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

a11mac = hmac SHA256.hash 64 hmacKey

