{-# LANGUAGE OverloadedStrings, CPP #-}
{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}

module Tests.JwkSpec where

import Test.Hspec
import Test.HUnit hiding (Test)

import Data.Aeson
#if MIN_VERSION_aeson(2,0,0)
import qualified Data.Aeson.KeyMap as KM
#else
import qualified Data.HashMap.Strict as H
#endif
import qualified Data.ByteString.Char8 as B
import Data.Word (Word64)
import qualified Data.Vector as V
import Crypto.PubKey.ECC.ECDSA
import Crypto.PubKey.ECC.Types
import Crypto.Random (drgNewTest, withDRG)

import Jose.Jwt (defJwsHdr, JwsHeader(..), KeyId(..))
import Jose.Jwk
import Jose.Jwa

spec :: Spec
spec = do
    jwkFile <- runIO (B.readFile "tests/jwks.json")
    let Just (Object keySet) = decodeStrict jwkFile
        Success s = fromJSON (Object keySet) :: Result JwkSet
        Just s'  = decode  (encode s)
        Just s'' = decode' (encode s')
        kss      = keys s'
        k0       = head kss
        k1       = kss !! 1
        k3       = kss !! 3
        k4       = kss !! 4
    describe "JWK encoding and decoding" $ do
        it "decodes and encodes an entire key set successfully" $ do
            let RsaPublicJwk  _ key0Id key0Use    a0   = k0
                RsaPublicJwk  _ key1Id key1Use    _    = k1
                EcPublicJwk   k key2Id key2Use    _ _  = kss !! 2
                EcPublicJwk _ key3Id key3Use  _ _      = k3
                SymmetricJwk _ key4Id Nothing _        = k4
                EcPublicJwk   _ key5Id (Just Enc) _ _  = kss !! 5
                RsaPublicJwk  _ key6Id Nothing    a6   = kss !! 6
                EcPrivateJwk  _ key7Id (Just Enc) _ _  = kss !! 7
                RsaPrivateJwk _ _      Nothing    a8   = kss !! 8
                Ed25519PrivateJwk _ _ key9Id = kss !! 9
                Ed25519PublicJwk _ key10Id = kss !! 10
                Success utcKeyId = fromJSON (String "2015-05-16T18:00:14.259Z")
            length kss @?= 14
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
            key9Id  @?= Just (KeyId "rfc8037SecretKey")
            key10Id  @?= Just (KeyId "rfc8037PublicKey")
            key0Use @?= Just Enc
            key1Use @?= Just Sig
            key2Use @?= Just Sig
            key3Use @?= Just Enc
            a6      @?= Just (Signed RS256)
            a8      @?= Just (Signed RS256)
            isPublic k3 @?= True
            isPublic k4 @?= False
            isPrivate k4 @?= False
        it "shameless Show and Eq coverage boosting" $ do
            s' @?= s''
            assertBool "Different sets aren't equal" (s' /= JwkSet { keys = take 8 kss ++ [k0]})
            assertBool "Show stuff" $ showCov s' && showCov k0 && showCov k3 && showCov Sig
            assertBool "Different keys should be unequal" (k0 /= k1)

    describe "Errors in JWK data" $ do
#if MIN_VERSION_aeson(2,0,0)
        let Just (Array ks) = KM.lookup "keys" keySet
#else
        let Just (Array ks) = H.lookup "keys" keySet
#endif
            Object k0obj = V.head ks
        it "invalid Base64 returns an error" $ do
#if MIN_VERSION_aeson(2,0,0)
            let result = fromJSON (Object $ KM.insert "n" (String "NotBase64**") k0obj) :: Result Jwk
#else
            let result = fromJSON (Object $ H.insert "n" (String "NotBase64**") k0obj) :: Result Jwk
#endif
            case result of
                Error _ -> assertBool "" True
                _       -> assertFailure "Expected an error for invalid base 64"

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

    describe "RSA Key generation" $ do
        let rng = drgNewTest (w, w, w, w, w) where w = 1 :: Word64
            kid = KeyId "mykey"
            ((kPub, kPr), _) = withDRG rng (generateRsaKeyPair 512 kid Sig Nothing)
        it "keys generated with same RNG are equal" $ do
            let ((kPub', kPr'), _) = withDRG rng (generateRsaKeyPair 512 kid Sig Nothing)
            kPub' @?= kPub
            kPr'  @?= kPr
        it "isPublic and isPrivate are correct for RSA keys" $ do
            isPublic kPub @?= True
            isPublic kPr  @?= False
            isPrivate kPr @?= True
        it "keys have supplied ID" $ do
            jwkId kPr  @?= Just kid
            jwkId kPub @?= Just kid
        it "keys have supplied use" $ do
            jwkUse kPr  @?= Just Sig
            jwkUse kPub @?= Just Sig
  where
    showCov x = showList [x] `seq` showsPrec 1 x `seq` show x `seq` True
