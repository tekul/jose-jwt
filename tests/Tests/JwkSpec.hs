{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}

module Tests.JwkSpec where

import Test.Hspec
import Test.HUnit hiding (Test)

import Data.Aeson
import Data.Aeson.QQ
import qualified Data.ByteString.Char8 ()
import Crypto.PubKey.ECC.ECDSA
import Crypto.PubKey.ECC.Types

import Jose.Jwt (defJwsHdr, JwsHeader(..), KeyId(..))
import Jose.Jwk
import Jose.Jwa

-- Some JSON keys to decode
-- TODO: Support for  {"kty": "oct", "alg": "A128KW", "k":"GawgguFyGrWKav7AX4VKUg"}
keySet :: Object
Object keySet = [aesonQQ|
   { "keys" :
        [ {"use": "enc", "n": "vnifEgZCnBxY5UDt3TJXp3_mNv92VWwHoc3B2oCuzgpgNyBwbBVIu3ScaflvQlntSgfo9VHiu16IqPuCOL4FjcY2RUZY7zizUZ2hFmmMThyx4HfTcDMNFOnetB1mKVUQ3gBOFjdnnj9auO4EK22xRcdB704XhES1TtYIiCxxfPOYBysCDHYcR-0KKjUPyXyhBGFoxiUrYP-c14Pf-aKWgNDqVlYlqayw9JHN4QVeJm8M5DHiPOtxO096Mc-5-X5NwXFMTzjywFWzkbFy7XmJj6BDmmh8-WUOBK1a9gy4zTysL9HfNhJIqi3BJUtLM_x2t-ISROm-Ud3y-4xgavXBTw", "e": "AQAB", "kty": "RSA", "kid": "a0"}
        , {"use": "sig", "n": "o9kJbxD1SgwrV_ottw7oHxxkjw83AuRrYbq8PzXDfhmvqvRHjhAOEGk1qDUbI8tkWzXsTuy-0UAvI9Xt3Qqmmk1MSkAx6K355_J1ofTafH5VrtPavC7HMVnz1zDebgwJH869jWHFghzL0Nr32zq4_V-gpt-zugKFpQi_LA9dtuAjcSTCMnDzTMw4WrMbzNOm90q0CkJCrWe6xM9z4Q_GCPgb2S4lsd5iNdtus9pG104wFAkgY7BXNP3hatYa1UVkAQdWMYyQATs6HMBZF4Ljf-upU9ic_vGwTGgunvQ7z29yrAFWaZQ-EqjYUnvQlmPFqMaNxg3TkPIgntqvZOdW_w", "e": "AQAB", "kty": "RSA", "kid": "a1"}
        , {"use": "sig", "crv": "P-256", "kty": "EC", "y": "kgFS_XvVOyuS41mBzmwJa-ik8Cy4rvM3uFncxmi_-Y8", "x": "bjX_T6O5OUW6WALJ173CH34TfzK9zEHycFT6KMWDnow", "kid": "a2"}
        , {"use": "enc", "crv": "P-256", "kty": "EC", "y": "zcOqE_LYsPTf7a9FOFpJiwK2ZQuUmoNLdsY7BRTICN0", "x": "6eXHDpNoiUaAR5Cle6rfmrVgksSagyi8fzvLF1kedKc", "kid": "a3"}
        , {"kty": "oct", "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", "kid":"HMAC key used in JWS A.1 example"}
        , {"kty":"EC", "crv":"P-256", "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "use":"enc", "kid":"1"}
        , {"kty":"RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e":"AQAB", "alg":"RS256", "kid":"2015-05-16T18:00:14.259Z"}
        , {"kty":"EC", "crv":"P-256", "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", "use":"enc", "kid":"1"}
        , {"kty":"RSA", "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e":"AQAB", "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q", "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs", "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk", "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0", "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk", "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU", "alg":"RS256", "kid":"2015-05-16T18:00:14.259Z"}
        ]
   }
|]


spec :: Spec
spec = do
    let Success s@(JwkSet _) = fromJSON (Object keySet) :: Result JwkSet
    describe "JWK encoding and decoding" $
        it "decodes and encodes an entire key set successfully" $ do
            let Just s' = decode' (encode s) :: Maybe JwkSet
                kss = keys s'
                RsaPublicJwk  _ key0Id key0Use    a0   = head kss
                RsaPublicJwk  _ key1Id key1Use    _    = kss !! 1
                EcPublicJwk   k key2Id key2Use    _ _  = kss !! 2
                EcPublicJwk   _ key3Id key3Use    _ _  = kss !! 3
                SymmetricJwk  _ key4Id Nothing    _    = kss !! 4
                EcPublicJwk   _ key5Id (Just Enc) _ _  = kss !! 5
                RsaPublicJwk  _ key6Id Nothing    a6   = kss !! 6
                EcPrivateJwk  _ key7Id (Just Enc) _ _  = kss !! 7
                RsaPrivateJwk _ _      Nothing    a8   = kss !! 8
                Success utcKeyId = fromJSON (String "2015-05-16T18:00:14.259Z")
            length kss @?= 9
            a0      @?= Nothing
            key0Id  @?= Just (KeyId "a0")
            key1Id  @?= Just (KeyId "a1")
            key2Id  @?= Just (KeyId "a2")
            public_curve k @?= getCurveByName SEC_p256r1
            key3Id  @?= Just (KeyId "a3")
            key4Id  @?= Just (KeyId "HMAC key used in JWS A.1 example")
            key5Id  @?= Just (KeyId "1")
            key6Id  @?= Just (UTCKeyId utcKeyId)
            key7Id  @?= Just (KeyId "1")
            key0Use @?= Just Enc
            key1Use @?= Just Sig
            key2Use @?= Just Sig
            key3Use @?= Just Enc
            a6      @?= Just (Signed RS256)
            a8      @?= Just (Signed RS256)

    describe "JWK Algorithm matching" $ do
        let jwks = keys s
        it "finds one key for RS256 encoding" $ do
            -- Only the RSA Private key
            let jwks' = filter (canEncodeJws RS256) jwks
            length jwks' @?= 1

        it "finds 3 keys for RS256 decoding with no kid" $ do
            -- All RSA keys are valid except for the "enc" one
            let jwks' = filter (canDecodeJws (defJwsHdr {jwsAlg = RS256})) jwks
            length jwks' @?= 3

        it "finds one key for RS256 decoding with kid specified" $ do
            let jwks' = filter (canDecodeJws (defJwsHdr {jwsAlg = RS256, jwsKid = Just (KeyId "a1")})) jwks
            length jwks' @?= 1

        it "finds an RS1_5 key for encoding" $ do
            -- Only key a0 matches. The other 3 RSA keys are signing keys
            let jwks' = filter (canEncodeJwe RSA1_5) jwks
            length jwks' @?= 1
