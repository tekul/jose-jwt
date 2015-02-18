{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}

module Tests.JwkSpec where

import Test.Hspec
import Test.HUnit hiding (Test)

import Data.Aeson
import Data.Aeson.QQ
import qualified Data.ByteString.Char8 ()
import Crypto.Types.PubKey.ECDSA
import Crypto.Types.PubKey.ECC

import Jose.Jwk

-- Some JSON keys to decode
keySet :: Object
Object keySet = [aesonQQ|
   { "keys" :
        [ {"use": "enc", "n": "vnifEgZCnBxY5UDt3TJXp3_mNv92VWwHoc3B2oCuzgpgNyBwbBVIu3ScaflvQlntSgfo9VHiu16IqPuCOL4FjcY2RUZY7zizUZ2hFmmMThyx4HfTcDMNFOnetB1mKVUQ3gBOFjdnnj9auO4EK22xRcdB704XhES1TtYIiCxxfPOYBysCDHYcR-0KKjUPyXyhBGFoxiUrYP-c14Pf-aKWgNDqVlYlqayw9JHN4QVeJm8M5DHiPOtxO096Mc-5-X5NwXFMTzjywFWzkbFy7XmJj6BDmmh8-WUOBK1a9gy4zTysL9HfNhJIqi3BJUtLM_x2t-ISROm-Ud3y-4xgavXBTw", "e": "AQAB", "kty": "RSA", "kid": "a0"}
        , {"use": "sig", "n": "o9kJbxD1SgwrV_ottw7oHxxkjw83AuRrYbq8PzXDfhmvqvRHjhAOEGk1qDUbI8tkWzXsTuy-0UAvI9Xt3Qqmmk1MSkAx6K355_J1ofTafH5VrtPavC7HMVnz1zDebgwJH869jWHFghzL0Nr32zq4_V-gpt-zugKFpQi_LA9dtuAjcSTCMnDzTMw4WrMbzNOm90q0CkJCrWe6xM9z4Q_GCPgb2S4lsd5iNdtus9pG104wFAkgY7BXNP3hatYa1UVkAQdWMYyQATs6HMBZF4Ljf-upU9ic_vGwTGgunvQ7z29yrAFWaZQ-EqjYUnvQlmPFqMaNxg3TkPIgntqvZOdW_w", "e": "AQAB", "kty": "RSA", "kid": "a1"}
        , {"use": "sig", "crv": "P-256", "kty": "EC", "y": "kgFS_XvVOyuS41mBzmwJa-ik8Cy4rvM3uFncxmi_-Y8", "x": "bjX_T6O5OUW6WALJ173CH34TfzK9zEHycFT6KMWDnow", "kid": "a2"}
        , {"use": "enc", "crv": "P-256", "kty": "EC", "y": "zcOqE_LYsPTf7a9FOFpJiwK2ZQuUmoNLdsY7BRTICN0", "x": "6eXHDpNoiUaAR5Cle6rfmrVgksSagyi8fzvLF1kedKc", "kid": "a3"}
        ]
   }

|]


spec :: Spec
spec =
    describe "JWK encoding and decoding" $
        it "decodes and encodes an entire key set successfully" $ do
            let Success s@(JwkSet _) = fromJSON (Object keySet) :: Result JwkSet
                Just s' = decode' (encode s) :: Maybe JwkSet
                kss = keys s'
                RsaPublicJwk _ key0Id key0Use a   = head kss
                RsaPublicJwk _ key1Id key1Use _   = kss !! 1
                EcPublicJwk  k key2Id key2Use _ _ = kss !! 2
                EcPublicJwk  _ key3Id key3Use _ _ = kss !! 3
            length kss @?= 4
            a       @?= Nothing
            key0Id  @?= Just "a0"
            key1Id  @?= Just "a1"
            key2Id  @?= Just "a2"
            key3Id  @?= Just "a3"
            key0Use @?= Just Enc
            key1Use @?= Just Sig
            key2Use @?= Just Sig
            key3Use @?= Just Enc
            public_curve k @?= getCurveByName SEC_p256r1

